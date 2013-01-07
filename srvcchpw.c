/*
    Copyright (C) 2009  Dmitriy Zaharov

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <string.h>
#include <windows.h>

/*
program args
-p passwd 
-u username
-s servicename
-h host
*/

void usage(char * app);
void memallocerr();
SC_HANDLE OpenActiveManager(char * host);
SC_HANDLE OpenNamedService(SC_HANDLE SCM,char * service);
void ChangeServiceLogon(char * ,char *, char *,char *);

int main(int argc,char ** argv)
{
  char * passwd = NULL;
  char * username = NULL;
  char * host = NULL;
  char * service = NULL;
  int passlen,usernamelen,hostlen,servicelen;
  int opt;

  while ( (opt = getopt(argc,argv,"p:u:h:s:")) !=-1){
    switch(opt){
    case 'u':
      usernamelen = (strlen(optarg) + 1);
      username = malloc(usernamelen);
      if (username == NULL){
	memallocerr();
      }
      strncpy(username,optarg,usernamelen);
      break;
    case 'p':
      passlen = (strlen(optarg) + 1);
      passwd = malloc(passlen);
      if (passwd == NULL){
	memallocerr();
      }
      strncpy(passwd,optarg,passlen);
      break;
    case 'h':
      hostlen = (strlen(optarg) + 1);
      host = malloc(hostlen);
      if (host == NULL){
	memallocerr();
      }
      strncpy(host,optarg,hostlen);
      break;
    case 's':
      servicelen = (strlen(optarg) + 1);
      service = malloc(servicelen);

      if (service == NULL) {
	memallocerr();
      }
      strncpy(service,optarg,servicelen);
      break;
    default:
      usage(argv[0]);
      exit(EXIT_FAILURE);

    }/*END CASE*/
  }/*END WHILE*/

  ChangeServiceLogon(username,passwd,host,service);

}

void ChangeServiceLogon(char * username,char * passwd,char * host,char * service)
{
  SC_HANDLE hManager;
  SC_HANDLE hService;
  int queryret,chret;
  QUERY_SERVICE_CONFIG * pServiceConfig;
  DWORD  scLen = 0;
  DWORD scNeedLen;
  DWORD err;

  hManager = OpenActiveManager(host);
  hService = OpenNamedService(hManager,service);

  queryret = QueryServiceConfig(hService,pServiceConfig,scLen,&scNeedLen);

  err = GetLastError();

  if (err != ERROR_INSUFFICIENT_BUFFER && queryret == 0 ){
    fprintf(stderr,"QueryServiceConfig Error\n");
    exit(EXIT_FAILURE);
  }

  pServiceConfig = malloc(scNeedLen);

  if(pServiceConfig == NULL){
    memallocerr();
  }
  
  scLen = scNeedLen;

  queryret = QueryServiceConfig(hService,pServiceConfig,scLen,&scNeedLen);

  /*prepare to call ChangeServiceConfig*/

  chret = ChangeServiceConfig(hService,
			      SERVICE_NO_CHANGE,
			      SERVICE_NO_CHANGE,
			      SERVICE_NO_CHANGE,
			      NULL,
			      NULL,
			      NULL,
			      NULL,
			      username,
			      passwd,
			      NULL);
  if (chret == 0){
    err = GetLastError();
    fprintf(stderr,"ChangeServiceConfig Windows error is: %d\n",err);
    exit(EXIT_FAILURE);
  }

}



SC_HANDLE OpenNamedService(SC_HANDLE SCM,char * service)
{
  SC_HANDLE hService;

  hService = OpenService(SCM,service,SC_MANAGER_ALL_ACCESS);
  if (hService == NULL){
    fprintf(stderr,"Error open service");
    exit(EXIT_FAILURE);
  }
}

SC_HANDLE OpenActiveManager(char * host)
{
  SC_HANDLE hManager;

  hManager = OpenSCManager(host,SERVICES_ACTIVE_DATABASE,SC_MANAGER_ALL_ACCESS);
  
  if (hManager == NULL){
    fprintf(stderr,"Error OPenSC");
    exit(EXIT_FAILURE);
  }

  return hManager;
}

void usage(char * app)
{
  fprintf(stderr,"Usage: %s -u username -p passwd -s service [-h host]",app);
}

void memallocerr()
{
  fprintf(stderr,"Error: malloc() unable allocate memory\n");
  exit(EXIT_FAILURE);
}
