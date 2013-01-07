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
#include <windows.h>
#include <stdio.h>
#include "win.h"



int main(int argc, char ** argv)
{

  struct acl acl;
  PSECURITY_DESCRIPTOR pSD = NULL;
  DWORD dwNeededLen = 0;
  struct ace * ace_cur = NULL;
  struct ace * ace_next = NULL;



  memset(&acl,0,sizeof(struct acl));

  GetFileSecurity(argv[1],
		  DACL_SECURITY_INFORMATION |
		  GROUP_SECURITY_INFORMATION|
		  OWNER_SECURITY_INFORMATION,
		  pSD,0,&dwNeededLen);

  pSD = (PSECURITY_DESCRIPTOR) malloc(dwNeededLen);
  if (pSD == NULL){
    fprintf(stderr,"Error: malloc()\n");
    exit(1);
  }
  if (0 == GetFileSecurity(argv[1],
			   DACL_SECURITY_INFORMATION |
			   GROUP_SECURITY_INFORMATION|
			   OWNER_SECURITY_INFORMATION,
			   pSD,dwNeededLen,&dwNeededLen))
    {
      fprintf(stderr,"Error: GetFileSecurity(), errno %d\n",
	      GetLastError());
      exit(1);
    }
  if (get_file_acl(pSD,&acl) == -1){
    fprintf(stderr,"Error: get_file_acl() errno %d\n",
	    GetLastError());
    exit(1);
  }
  free(pSD);
  
  printf("Owner:%s\n",acl.owner);
  printf("Group:%s\n",acl.group);

  
  if (acl.list_ace != NULL){
    ace_cur = acl.list_ace;

    while(ace_cur->next != NULL){
      printf("%s\n",ace_cur->ap);
      ace_cur = ace_cur->next;
    }
  
  
    /*Free Memory*/
    ace_cur = acl.list_ace;
    while(ace_cur->next != NULL){
      ace_next = ace_cur->next;
      free(ace_cur);
      ace_cur = ace_next;
    }
  }
}
