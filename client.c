#include "main.h"
#define BUF_SIZE 100
#define NAME_SIZE 20

unsigned WINAPI SendMsg(void* arg);
unsigned WINAPI RecvMsg(void* arg);
void ErrorHandling(char* msg);

char name[NAME_SIZE] = "[DEFAULT]";
char msg[BUF_SIZE];

typedef struct USER {
	char myIp[100];
	char port[100];
	char inputName[100];
	char inputPW[100];
	char reinputPW[100];

} USER;
USER user,loginuser;

typedef struct DATA {
	struct USER datanum[10];
};
int retval,length;
FILE* key_f = NULL; //������ ����Ű ���� ������
FILE* crt_f = NULL; // ������ ������ ���� ������ 
int sign_len; // ���ΰ� ����(����Ű ��ȣȭ�� ����� ����)
unsigned char sign[256]; //���ΰ��� ��� ����(����Ű�� ��ȣȭ�� ������� ��� 
int d_sign_len; // ���ΰ� ��ȣȭ ����
unsigned char d_sign[256]; // ���ΰ� ��ȣȭ�� ���� ��� ����
unsigned char bufferEnc[256];
unsigned char bufferDec[256];
int main() {
	int select;
	WSADATA wsaData;
	SOCKET sock;
	SOCKADDR_IN serverAddr;
	HANDLE sendThread, recvThread;
	int i;
	int loginSwitch = 0,idSwitch = 0;
	struct DATA data;
	FILE* fp,*fpr,*fps;
	BYTE Key[] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
	BYTE EncBuff1[80];
	BYTE EncBuff2[80];
	char DecBuff_Name[80];
	char DecBuff_PW[80];
	BYTE DecBuff1[80];
	BYTE DecBuff2[80];
	char calc_hash[65];
	int  I, Len,Len1,Len2,LenSum;
	while (1) {

		printf("1 : ȸ������ \n2 : �α��� \n3 : ���� ����\n>>");

		scanf("%d", &select);

		if (select == 1) {
			while (1) {
				fp = fopen("UserinfoEnc.txt", "a");
				fps = fopen("Userid.txt", "a+");
				printf("������ ���̵� �Է��ϼ��� : ");
				scanf("%s", user.inputName);

				for (i = 0; i < 10; i++)
				{
					fscanf(fps, "%s\n", (const char*)data.datanum[i].inputName);
				}
				for (i = 0; i < 10; i++)
				{
					if (strcmp(user.inputName, data.datanum[i].inputName) == 0) {
						idSwitch = 1;
					}
				}

				if (idSwitch == 1) {
					printf("���̵� �ߺ��Դϴ�. ����� �ʱ�ȭ������ �Ѿ�ϴ�. \n");
					idSwitch = 0;
					Sleep(3000);
					system("cls");
					break;
				}
				else if (idSwitch == 0) {
					fprintf(fps, "%s\n", user.inputName);
					printf("��й�ȣ �Է� : ");
					scanf("%s", user.inputPW);

					printf("��й�ȣ ���Է� : ");
					scanf("%s", user.reinputPW);

					if (user.inputPW == user.reinputPW) {
						break;
					}

					Len1 = strlen(user.inputName) + 1;
					Len2 = strlen(user.inputPW) + 1;
					LenSum = Len1 + Len2;

					AES_ECB_Encrypt(user.inputName, Key, EncBuff1, Len1);
					AES_ECB_Encrypt(user.inputPW, Key, EncBuff2, Len2);

					for (I = 0; I < LenSum; I++) {
						fprintf(fp, "%02X", EncBuff1[I]);
					}

					fprintf(fp, " ");

					for (I = 0; I < LenSum; I++) {
						fprintf(fp, "%02X", EncBuff2[I]);
					}

					fprintf(fp, "\n");
					fclose(fps);
					fclose(fp);
				}
				else {
					printf("�ùٸ� ���� �Է��Ͻÿ�.");
					system("cls");
					break;
				}
				break;
			}
		}
		
		else if (select == 2) {
			fp = fopen("UserinfoEnc.txt", "r");
			for (i = 0; i < 10; i++)
				fscanf(fp, "%s %s\n", (const char*)data.datanum[i].inputName, (const char*)data.datanum[i].inputPW);
			while (1) {
				printf("���̵� : ");
				scanf("%s", user.inputName);

				printf("��й�ȣ : ");
				scanf("%s", user.inputPW);

				fclose(fp);

				fpr = fopen("UserinfoDec.txt", "w");

				Len1 = strlen(user.inputName) + 1;
				Len2 = strlen(user.inputPW) + 1;
				LenSum = Len1 + Len2;

				AES_ECB_Encrypt(user.inputName, Key, DecBuff1, Len1);
				AES_ECB_Encrypt(user.inputPW, Key, DecBuff2, Len2);

				for (I = 0; I < LenSum; I++) {
					fprintf(fpr, "%02X", DecBuff1[I]);
				}

				fprintf(fpr, " ");

				for (I = 0; I < LenSum; I++) {
					fprintf(fpr, "%02X", DecBuff2[I]);
				}

				fprintf(fpr, "\n");

				fclose(fpr);

				fpr = fopen("UserinfoDec.txt", "r");
				fscanf(fpr, "%s %s\n", (const char*)DecBuff_Name, (const char*)DecBuff_PW);
				_unlink("");

				fclose(fpr);
				fpr = fopen("UserinfoDec.txt", "w");
				fprintf(fpr, "NULL");
				fclose(fpr);
				fclose(fp);

				for (i = 0; i < 10; i++)
				{
					if (strcmp(DecBuff_Name, data.datanum[i].inputName) == 0 && strcmp(DecBuff_PW, data.datanum[i].inputPW) == 0)
						loginSwitch = 1;
				}

				if (loginSwitch == 1)
				{
					printf("�α��ο� �����ϼ̽��ϴ�.\n");
					fp = fopen("login data.txt", "a");
					fprintf(fp, "login user: %s \n", user.inputName);
					fclose(fp);
					break;
				}
				else {
					printf("���̵�� �н����尡 ��ġ���� �ʽ��ϴ�.\n");
					system("cls");
					continue;
				}
			}
			printf("Input server port : ");
			scanf("%s", user.port);
			break;
		}
		else if (select == 3) {
			system("cls");
			printf("����Ǿ����ϴ�.");
			return 0;
		}
		else {
			printf("�α��ο� �����ϼ̽��ϴ�.\n");
			system("cls");
			continue;
		}

	}

	system("cls");
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
		ErrorHandling("���� ���� ����");

	sprintf(name, "[%s]", user.inputName);
	sock = socket(PF_INET, SOCK_STREAM, 0);

	memset(&serverAddr, 0, sizeof(serverAddr));
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serverAddr.sin_port = htons(atoi(user.port));

	if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR)
		ErrorHandling("��Ʈ�� �߸� �Է� �Ͽ����ϴ�");


	sendThread = (HANDLE)_beginthreadex(NULL, 0, SendMsg, (void*)&sock, 0, NULL);
	recvThread = (HANDLE)_beginthreadex(NULL, 0, RecvMsg, (void*)&sock, 0, NULL);



	int len = sizeof(user);
	retval = send(sock, (char*)&len, sizeof(int), 0);
	if (retval == SOCKET_ERROR) {
		ErrorHandling("���� retval ����");
		exit(1);
	}

	retval = send(sock, (char*)&user, sizeof(USER), 0);
	if (retval == SOCKET_ERROR) {
		ErrorHandling("���� retval ����");
		exit(1);
	}

	WaitForSingleObject(sendThread, INFINITE);
	WaitForSingleObject(recvThread, INFINITE);
	
	closesocket(sock);
	WSACleanup();
	return 0;
}

unsigned WINAPI SendMsg(void* arg) {
	SOCKET sock = *((SOCKET*)arg);
	char nameMsg[NAME_SIZE + BUF_SIZE];
	while (1) {
		fgets(msg, BUF_SIZE, stdin);
		if (!strcmp(msg, "q\n")) {
			send(sock, "�����̽��ϴ�.", 1, 0);
			closesocket(sock);
			exit(0);
		}
		sprintf(nameMsg, "%s %s", name, msg);
		send(sock, nameMsg, strlen(nameMsg), 0);
	}
	return 0;
}

unsigned WINAPI RecvMsg(void* arg) {
	SOCKET sock = *((SOCKET*)arg);
	char nameMsg[NAME_SIZE + BUF_SIZE];
	int strLen;
	while (1) {
		strLen = recv(sock, nameMsg, NAME_SIZE + BUF_SIZE - 1, 0);
		if (strLen == -1)
			return -1;
		nameMsg[strLen] = 0;
		fputs(nameMsg, stdout);
	}
	return 0;
}

void ErrorHandling(char* msg) {
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}
