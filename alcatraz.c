/*  INF3173 - TP0 
 *  Session : automne 2021
 *  Tous les groupes
 *  
 *  IDENTIFICATION.
 *
 *      Nom : Hamel Bourdeau
 *      Prénom : Alexandre
 *      Code permanent : HAMA12128907
 *      Groupe : 20
 */

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static int install_filter(int syscall_nr) {
    struct sock_filter filter[] = {
        /* Load current architecture */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),
        
        /* Compare with specified architecture, jump if different */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 2),        
        
        /* Load system call */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),
        
        /* Compare syscall with blocked syscall, jump if different */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, syscall_nr, 0, 1),
        
        /* Kill process if arch is different or syscall is blocked */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        
        /* Allow system call when arch is the same and syscall is not blocked */
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
    };

    struct sock_fprog prog = {
        .len = ARRAY_SIZE(filter),
        .filter = filter
    };
    
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int main(int argc, char **argv) {
    int main_result = 0;
    pid_t pid = fork();
    
    if (pid == -1) {
        main_result = 1;
    
    } else if (pid == 0) {
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0);
       
        char * pointer;
        pointer = strtok(argv[1], ",");
        while (pointer != NULL) {
            int syscall_nr = atoi(pointer);
            pointer = strtok(NULL, ",");
            install_filter(syscall_nr);
        }

        char * new_env[] = {NULL};
        execve(argv[2], &argv[2], new_env);
        
    } else {
        int status;
        waitpid(pid, &status, WUNTRACED);
    
        if (WIFEXITED(status) == 1) {        
            printf("%i", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status) == 1) {     
            printf("%i", WTERMSIG(status));
            main_result = 1;
        } else {
            main_result = 1;
        }
    }

    return main_result;
}
