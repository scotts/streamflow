/*
 * recycle.c
 *
 * Copyright (C) 2007  Scott Schneider, Christos Antonopoulos
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <numa.h>

size_t min_size;
size_t max_size;
int iterations = (int)1e8;
int rate;

#include <sys/types.h>
#include <linux/unistd.h>

void discover_cpu()
{
	FILE* stats;
	unsigned int cpu;
	int dint;
	char tcomm[16];
	char stat;
	long dlong;
	unsigned long dulong;
	unsigned long long dullong;
	char buffer[512];
	char proc[] = "/proc/self/task/";

	strcpy(buffer, proc);
	sprintf(buffer + strlen(proc), "%lu", syscall(__NR_gettid));
	strcpy(buffer + strlen(buffer), "/stat");

	if ((stats = fopen(buffer, "r")) == NULL) {
		perror("discover_cpu");
		exit(1);
	}

	fscanf(stats, "%d %s %c %d %d %d %d %d %lu %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %d %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %d %d %lu %lu\n",
			&dint,
			tcomm,
			&stat,
			&dint, &dint, &dint, &dint, &dint,
			&dulong, &dulong, &dulong, &dulong, &dulong, &dulong, &dulong,
			&dlong, &dlong, &dlong, &dlong,
			&dint, 
			&dlong,
			&dullong,
			&dulong,
			&dlong,
			&dulong, &dulong, &dulong, &dulong, &dulong, &dulong, &dulong, 
			&dulong, &dulong, &dulong, &dulong, &dulong, &dulong,
			&dint, 
			&cpu, 
			&dulong,
			&dulong);

	printf("thread %d on cpu %d\n", syscall(__NR_gettid), cpu);
	fflush(stdout);

	fclose(stats);
}
double random_number()
{
	static long int seed = 547845897;
	static long int m = 2147483647;         // m is the modulus, m = 2 ^ 31 - 1
	static long int a = 16807;              // a is the multiplier, a = 7 ^ 5
	static long int q = 127773;             // q is the floor of m / a
	static long int r = 2836;               // r is m mod a

	long int temp = a * (seed % q) - r * (seed / q);

	if (temp > 0) {
		seed = temp;
	}
	else {
		seed = temp + m;
	}

	return (double)seed / (double)m;
}

void* simulate_work(void* arg)
{
	unsigned long** reserve = (void**)malloc(rate * sizeof(void*));
	int i;
	int j;
	double rand;
	size_t object_size;

	for (i = 0; i < iterations; ++i) {

		/*
		if (i % (int)1e6 == 0) {
			discover_cpu();
		}
		*/
		if (i % rate == 0 && i != 0) {
			for (j = 0; j < rate; ++j) {
				free(reserve[j]);
			}
		}

		rand = random_number();
		object_size = min_size + (rand * (max_size - min_size));
		reserve[i % rate] = malloc(object_size);
	}

	free(reserve);

	return NULL;
}

void numa_start(void);

int main(int argc, char* argv[])
{
	pthread_t* threads;

	//numa_start();

	int num_threads = atoi(argv[1]);
	min_size = atoi(argv[2]);
	max_size = atoi(argv[3]);
	rate = atoi(argv[4]);

	iterations /= num_threads;

	threads = (pthread_t*)malloc(num_threads * sizeof(pthread_t));

	int i;
	for (i = 0; i < num_threads-1; ++i) {
		pthread_create(&threads[i], NULL, simulate_work, NULL);
	}

	simulate_work(NULL);
	
	for (i = 0; i < num_threads-1; ++i) {
		pthread_join(threads[i], NULL);
	}

	return 0;
}

