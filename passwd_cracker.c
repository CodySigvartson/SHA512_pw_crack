#include <crypt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define SHDW_LINE_LEN 256
#define WORD_LEN 80

int is_desired_user(char *userid);


int main(){

	FILE *shadow;
	FILE *dict;

	char *uids[5];
	char *salts[5];
	char *hashes[5];


	shadow = fopen("/etc/shadow", "r");
	if(shadow == NULL){
		fprintf(stderr, "Cannot open shadow file \n");
		exit(1);
	}

	dict   = fopen("/etc/dictionaries-common/words", "r");
	if(dict == NULL){
		fprintf(stderr, "Cannot open dict file\n");
		exit(1);
	}

	char shdw_line[SHDW_LINE_LEN];
	int num_accounts = 0;
	while(fgets(shdw_line, SHDW_LINE_LEN, shadow)!=NULL){
		char *token = strtok(shdw_line, ":");
		printf("ID: %s\n", token);
		if(is_desired_user(token) > 0){
			uids[num_accounts] = malloc(10);
			strcpy(uids[num_accounts],token);
			char *shdw_hash = strtok(NULL, ":");
			if(strcmp(shdw_hash, "*")!=0 && strcmp(shdw_hash, "!")!=0){
				token = strtok(shdw_hash, "$");
				token = strtok(NULL, "$");
				char final_salt[11] = {'$','6','$'};
				salts[num_accounts] = malloc(50);
				strcat(final_salt,token);
				strcpy(salts[num_accounts],final_salt);
				printf("  salt: %s\n", token);
				token = strtok(NULL, "$");
				printf("  hash: %s\n", token);
				hashes[num_accounts] = malloc(300);
				strcat(hashes[num_accounts],final_salt);
				strcat(hashes[num_accounts],"$");
				strcat(hashes[num_accounts],token);
				num_accounts++;
			}
		}
	}


	for(int j = 0; j < num_accounts; j++){
		printf("UID: %s\n", uids[j]);
		printf("Salt: %s\n", salts[j]);
		printf("Hash: %s\n", hashes[j]);
	}


	char word[WORD_LEN];
	while(fgets(word, WORD_LEN, dict)!=NULL){
		word[strlen(word)-1] = 0;
		for(int i=0; i<num_accounts; i++){
			char *hash = crypt(word,salts[i]);
			char hash_final[strlen(hash)];
			memset(hash_final,'\0',sizeof(hash_final));
			strcpy(hash_final,hash);
			if(strcmp(hash_final,hashes[i]) == 0){
				printf("UserID: %s\n", uids[i]);
				printf("Password: %s\n", word);
			}
		}
	}
}


int is_desired_user(char *userid){
if(strcmp(userid,"user1") == 0 || strcmp(userid,"user2") == 0 || strcmp(userid,"user3") == 0 ||
	strcmp(userid,"user4") == 0 || strcmp(userid,"user5") == 0)
	return 1;
return 0;
}
