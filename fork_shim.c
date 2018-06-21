/**************************************************************************************
 fork_shim.c v0.1

 Code that attempts to efficiently set the OOM killer "oom_score_adj" value to 1000
 for all forked PIDs that are created by puppet (or any other daemon/tool that forks
 or spawns children that may become an issue).  This means the forked PIDs are in
 queue to be killed by OOM killer before anything else if system memory becomes
 exhausted.


 There is also support for whitelisting processes and process flags so that they
 will become immune to being killed by OOM killer.  Simply add the process or flag
 name to: /etc/oom_whitelist
 By default, entries in the whitelist file will be used as the main string against
 substrings searches, which are the forked process names and flags.
 i.e. if "sshd" is whitelisted, something that forks 'sh -c "whoami"' will become
 whitelisted, since 'sh' is a substring within 'sshd'.
 To prevent substring matches, prepend your whitelist entries with '!'
 i.e. !sshd
 This will ensure only 'sshd' matches.  Keep substring and non substring syntax in
 mind when creating your whitelist file, as for they both have their use cases.


 HOW TO COMPILE:
 $ gcc -fPIC -c -Wall fork_shim.c
 $ gcc -shared fork_shim.o -ldl -lstdc++ -o fork_shim.so

 USAGE:
 # LD_PRELOAD=/path/to/shim_fork.so /opt/puppetlabs/bin/puppet agent -t

 LOG FILES:
 /tmp/shim_forks_wl.log  [will detail the process (and flags) being checked for]
 /tmp/shim_forks.log     [will detail the process IDs being checked]

 Author: Cody Tubbs (codytubbs@gmail.com) Sep 2017

*************************************************************************************/

#include <dlfcn.h>   // dlsym()
#include <stdio.h>   // FILE, fopen(), fprintf(), fclose(), snprintf(), fgets()
#include <string.h>  // strrchr(), strlen(), strstr(), strtok()
#include <unistd.h>  // access()
#include <stdlib.h>  // free()

int check_wl_config(const char *proc_name);

pid_t fork(void){
    FILE *logFile = fopen("/tmp/shim_forks.log", "a"); // Location for debugging list of pids.
    int oomValue = 1000;        // define as highest value for oom_score_adj ... death row
    int whitelistValue = -1000; // define as lowest value for oom_score_adj ... never kill
    char fileName[25+1];    // max pid is 65535; (i.e. /proc/65535/oom_score_adj) = len 25
    char cmdFileName[19+1]; // max pid is 65535; (i.e. /proc/65535/cmdline) = len 19
    typedef pid_t (*t_fork)(void);
    t_fork org_fork = dlsym(((void *) -1l), "fork");
    pid_t pid = org_fork();
    if(pid != 0){
        fprintf(logFile, "pid = %i\n", pid); // tmp during dev
        fclose(logFile); // ''
    } else {
        return pid;
    }
    snprintf(fileName, sizeof(fileName), "/proc/%d/oom_score_adj", pid);
    snprintf(cmdFileName, sizeof(cmdFileName), "/proc/%d/cmdline", pid);
    // check if /proc/$PID/oom_score_adj exists...
    if(access(fileName, F_OK) != -1){
        FILE *oomFile = fopen(fileName, "w");
        // pid exists, let's hope we can write to it fast enough before it goes away (if it's short living)...
        // check if /proc/$PID/cmdline exists...
        if(access(cmdFileName, F_OK) != -1){
            // cmdline proc file exists, let's quickly read the entry...
            //printf("debug fork(): cmdFileName=[%s] accessible, opening...\n", cmdFileName);
            // this is not a standard flat-file, handle accordingly...
            FILE *cmdFile = fopen(cmdFileName, "rb");
            char *cmdArg = 0;
            size_t size = 0;
            while(getdelim(&cmdArg, &size, 0, cmdFile) != -1){
                // check each arg against whitelist and whitelist accordingly.
                //printf("debug fork(): original, cmdArg=[%s]...\n", cmdArg);
                // use strrchr to grab the command after the last forward slash, e.g. sshd from /usr/sbin/sshd [DONE]
                const char separator = '/';
                if(cmdArg[0] == '/'){
                    char * const afterSlash = strrchr(cmdArg, separator);
                    if(afterSlash[0] == '/') {
                        //printf("debug: fork(): strrchr cmdArg=[%s], ", cmdArg); // print before the last slash gets overwritten after memmove()
                        memmove(afterSlash, afterSlash + 1, strlen(afterSlash)); // rewind over the leading slash!
                        char* token = strtok(afterSlash, " ");
                        // check all flags as being whitelisted, i.e. when sh -c is used... e.g. sh -c "sh -c 'id'" [DONE]
                        while (token) {
                            token = strtok(NULL, " ");
                            if (check_wl_config(token) == 1) { // proccess or flag is whitelisted...
                                fprintf(oomFile, "%i\n", whitelistValue);
                                fclose(oomFile);
                                free(cmdArg);
                                free(token);
                                fclose(cmdFile);
                                return pid;
                            }
                        }
                    }
                } else {
                    if(check_wl_config(cmdArg) == 1) { // proccess is whitelisted...
                        fprintf(oomFile, "%i\n", whitelistValue);
                        fclose(oomFile);
                        free(cmdArg);
                        fclose(cmdFile);
                        return pid;
                    }
                }
            }
            fclose(cmdFile);
            fprintf(oomFile, "%i\n", oomValue);
            fclose(oomFile);
            return pid;
        }
    } else {
            // pid must have already came and gone, which means it didn't need our help.
    }
    return pid;
}

int check_wl_config(const char *proc_name){
    FILE *logFile = fopen("/tmp/shim_forks_wl.log", "a");
    FILE *whitelist_file;
    char *fileName = "/etc/oom_whitelist";
    char wl_proc_name[128+1], real[128+1], last[128+1];
    int catch_bad_things = 0;
    //printf("debug: proc_name=[%s]\n", proc_name);

    if(access(fileName, F_OK) == -1){
        //printf("debug: /etc/oom_whitelist not found, skipping...");
        fclose(logFile);
        return(0);
    }
    if((whitelist_file=fopen(fileName, "r")) == NULL){
        //printf("Error, couldn't open '%s' process whitelist file!\n", fileName);
        fclose(logFile);
        return(0);
    }
    fprintf(logFile, "checking for proc/flag name = [%s]\n", proc_name);
    while(fgets(wl_proc_name, sizeof(wl_proc_name)-1, whitelist_file) != NULL){
        //printf("X: wl_proc_name=[%s]\n", wl_proc_name);
        if(!strstr(wl_proc_name, "\n")){ // fgets read too little and rolled over, or entry is missing a newline
            catch_bad_things++;
            continue; // prevent potentially truncated entries from fgets from actually matching (case of >sizeof)
        }
        snprintf(real, sizeof(real)-1, "%s", wl_proc_name);
        wl_proc_name[strlen(wl_proc_name)-1] = 0x00;

        if(strlen(wl_proc_name) == 0){ // skip empty lines in the whitelist conf
            continue;
        } else {
            if(wl_proc_name[0] == '#'){ // skip lines that are punched out
                continue;
            }else{
                if((last[strlen(last)-1] != '\n') && (catch_bad_things > 0)){
                    // caught: str < sizeof rollover from fgets (due to prior >sizeof) attempting to be a new entry... clever.
                    snprintf(last, sizeof(last)-1, "%s", real);
                    continue;
                }
                // Allow for non-substring whitelist entries, prepended by a bang.
                if(wl_proc_name[0] == '!'){
                    memmove(wl_proc_name, wl_proc_name+1, strlen(wl_proc_name)); // rewind over the bang
                    if(!strcmp(wl_proc_name, proc_name)){
                        fprintf(logFile, "proc/arg name=[%s] is whitelisted. Fully matched [%s] entry, setting -1000\n", proc_name, wl_proc_name);
                        fclose(logFile); // tmp while debugging

                        return(1);
                    }
                } else {
                    // if commands aren't prepended with a bang, they are sub searched.  "sshd" will allow "sh" to become whitelisted.
                    if (strstr(wl_proc_name, proc_name) != NULL) {
                        fprintf(logFile, "proc/arg name=[%s] is whitelisted due to substring matching [%s], setting -1000\n", proc_name, wl_proc_name);
                        fclose(logFile); // tmp while debugging
                        return(1);
                    }
                }
                snprintf(last, sizeof(last)-1, "%s", real);
                catch_bad_things++;
            }
        }
    }
    fclose(logFile);
    return(0);
}
