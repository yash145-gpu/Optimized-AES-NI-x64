#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/time.h>

#define RUN_COUNT 10

double get_time() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + tv.tv_usec / 1000000.0;
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <prog1> <prog2> ...\n", argv[0]);
        return 1;
    }
    
    double times[argc-1];
    
    for (int i = 1; i < argc; i++) {
        printf("Testing %s:\n", argv[i]);
        double start = get_time();
        
        for (int run = 0; run < RUN_COUNT; run++) {
            pid_t pid = fork();
            if (pid == 0) {
                // Child
                execl(argv[i], argv[i], NULL);
                exit(1);
            } else {
                wait(NULL);
            }
        }
        
        double end = get_time();
        times[i-1] = end - start;
        printf("  Time: %.4f seconds (avg: %.4f)\n", 
               times[i-1], times[i-1]/RUN_COUNT);
        
        sleep(1);
    }
    
    printf("\nSummary:\n");
    for (int i = 1; i < argc; i++) {
        printf("%s: %.4f seconds\n", argv[i], times[i-1]);
    }
    
    return 0;
}
