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
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>
#include "win.h"



/*
(in) PSECURITY_DESCRIPTOR file or directory handle
(in/out) struct acl * acl 
*/
int get_file_acl(PSECURITY_DESCRIPTOR pSD,struct acl * acl)
{
  DWORD dwLastError;
  PACL pDacl;
  PSID pOwnerSid,pGroupSid;
  SID_NAME_USE eUse;
  BOOL  bPresent;
  BOOL bDef;
  int i;


  
  if (0 == GetSecurityDescriptorOwner(pSD,
				      &pOwnerSid,
				      &bDef)){
    return (-1);
  }
  if (0 == GetSecurityDescriptorGroup(pSD,
				      &pGroupSid,
				      &bDef)){
    return(-1);
  }
  if (0 == GetSecurityDescriptorDacl(pSD,&bPresent,&pDacl,&bDef)){
    return(-1);
  }

  if (get_account_sid(pOwnerSid,acl->owner,MAX_LEN,&eUse) == -1){
    return (-1);
  }
  if (get_account_sid(pGroupSid,acl->group,MAX_LEN,&eUse) == -1){
    return (-1);
  }

  if (pDacl != NULL)
    get_ace(pDacl,acl,&eUse);


  return (0);
}
/*
  (in) PSID pSid
  (out) char ** account
  (in/out) SID_NAME_USE * peSid
return value
   0 - SUCCESS
  -1 - Error 
*/

int get_account_sid(PSID pSid,char * account,size_t acclen,
		    SID_NAME_USE * peUse)
{
  DWORD dwAccountLen = 0;
  DWORD dwDomainLen = 0;
  char * szAccountName = NULL;
  char * szDomainName = NULL;
  DWORD dwRetLen = 0;
  

  LookupAccountSid(NULL,pSid,
		   szAccountName,&dwAccountLen,
		   szDomainName,&dwDomainLen,
		   peUse);


  szAccountName = (char *) malloc(dwAccountLen);

  if (szAccountName == NULL){
    SetLastError(ERROR_OUTOFMEMORY);
    return (-1);
  }

  szDomainName = (char *) malloc(dwDomainLen);

  if (szDomainName == NULL){
    free(szAccountName);
    SetLastError(ERROR_OUTOFMEMORY);
    return (-1);
  }

  if (0 == LookupAccountSid(NULL,pSid,
			    szAccountName,&dwAccountLen,
			    szDomainName,&dwDomainLen,
			    peUse)){
    if (GetLastError() == ERROR_NONE_MAPPED){
      get_textual_sid(pSid,account,acclen);
      goto free_mem;
    }
    free(szAccountName);
    free(szDomainName);
    return (-1);
  }



  if (dwDomainLen <= 1)
    _snprintf(account,acclen,"%s",szAccountName);
  else
    _snprintf(account,acclen,"%s\\%s",szDomainName,szAccountName);
  
  
 free_mem:
  free(szAccountName);
  free(szDomainName);

  return (0);
}

/*
  (in) pAcl
  (in/out) struct acl *
  (in/out) SID_NAME_USE *
return value
0 in sucess
-1 on error
*/
int get_ace(PACL pAcl,struct acl * acl,SID_NAME_USE * peUse)
{
  ACL_SIZE_INFORMATION ASizeInfo;
  PACCESS_ALLOWED_ACE pAce;
  PSID pAceSid;
  int i;
  struct ace * ace_cur;
  char ace_pref[3];
  char ace_post[5];
  char buf[MAX_LEN];


  if(0 == GetAclInformation(pAcl,&ASizeInfo,
			    sizeof(ACL_SIZE_INFORMATION),
			    AclSizeInformation)){
    return (-1);
  }

  ace_cur = (struct ace *) malloc(sizeof(struct ace));
  if (ace_cur == NULL){
    SetLastError(ERROR_OUTOFMEMORY);
    return(-1);
  } else {
    ace_cur->next = NULL;
  }
  acl->list_ace = ace_cur;


  for (i = 0; i < ASizeInfo.AceCount;i++){
    strncpy(ace_pref,ACL_PREFIX,sizeof(ace_pref));
    strncpy(ace_post,ACL_POSTFIX,sizeof(ace_post));

    if (0 == GetAce(pAcl,i,&pAce))
      return (-1);

  pAceSid = (PSID) &pAce->SidStart;
  if (-1 == get_account_sid(pAceSid,buf,MAX_LEN,peUse)){
    fprintf(stderr,"%d\n",GetLastError());
    return(-1);
   }
  switch (*peUse){
        case SidTypeUser:
	  ace_pref[ACL_USER_POS] = ACL_USER;
	  break;
        case SidTypeGroup:
	  ace_pref[ACL_USER_POS] = ACL_GROUP;
	  break;
        default:
	  ace_pref[ACL_USER_POS] = ACL_USER;
	  break;
  };
  
  if(pAce->Header.AceType == ACCESS_ALLOWED_ACE_TYPE){
    if ( (pAce->Mask & FILE_READ_DATA) == FILE_READ_DATA)
      ace_post[ACL_READ_POS] = ACL_READ;
    if ( (pAce->Mask & FILE_WRITE_DATA) == FILE_WRITE_DATA)
      ace_post[ACL_WRITE_POS] = ACL_WRITE;
    if ( (pAce->Mask & FILE_EXECUTE) == FILE_EXECUTE)
      ace_post[ACL_EXECUTE_POS] = ACL_EXECUTE;
    if ((pAce->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS){
      ace_post[ACL_READ_POS] = ACL_READ;
      ace_post[ACL_WRITE_POS] = ACL_WRITE;
      ace_post[ACL_EXECUTE_POS] = ACL_EXECUTE;
      }
  }
  _snprintf(ace_cur->ap,MAX_LEN -1,"%s%s%s",ace_pref,buf,ace_post);
  
  ace_cur->next = (struct ace *) malloc(sizeof(struct ace));
  if (ace_cur->next == NULL){
    SetLastError(ERROR_OUTOFMEMORY);
    return(-1);
  } else {
    ace_cur = ace_cur->next;
    ace_cur->next = NULL;
  }
  }
  return(0);
}

/*
  (in) PSID 
  (in/out) char 
  (in) size_t
return
  0 - success
 -1 - error
*/
int get_textual_sid(PSID pSid,char * buf,size_t len)
{
  /*FROM MSDN Converting a Binary SID to String Format in C++*/
  PSID_IDENTIFIER_AUTHORITY psia;
  DWORD dwSubAuthorities;
  DWORD dwSidRev = SID_REVISION;
  DWORD dwCounter;
  DWORD dwSidSize;

  if (!IsValidSid(pSid)){
    SetLastError(ERROR_INVALID_DATA);
    return -1;
  }
  psia = GetSidIdentifierAuthority(pSid);

  dwSubAuthorities = *GetSidSubAuthorityCount(pSid);

  dwSidSize = (15 + 12 + (12 * dwSubAuthorities) +1) * sizeof(char);

  if (len < dwSidSize){
    SetLastError(ERROR_INSUFFICIENT_BUFFER);
    return -1;
  }

  _snprintf(buf,len,"S-%lu-",dwSidRev);

  if ( (psia->Value[0] != 0) || (psia->Value[1] != 0) ){
    _snprintf(buf + strlen(buf),len-(strlen(buf)+1),
	    "0x%02hx%02hx%02hx%02hx%02hx%02hx",
	    (USHORT) psia->Value[0],
	    (USHORT) psia->Value[1],
	    (USHORT) psia->Value[2],
	    (USHORT) psia->Value[3],
	    (USHORT) psia->Value[4],
	    (USHORT) psia->Value[5]);
  }else {
    _snprintf(buf + strlen(buf),len - (strlen(buf)+1),
	      "%lu",
	      (USHORT) (psia->Value[5])      +
	      (USHORT) (psia->Value[4] <<  8)+
	      (USHORT) (psia->Value[3] << 16)+
	      (USHORT) (psia->Value[2] << 24));
  }

  for (dwCounter = 0; dwCounter < dwSubAuthorities; dwCounter++){
    _snprintf(buf + strlen(buf),len - (strlen(buf)+1),"-%lu",
	      *GetSidSubAuthority(pSid,dwCounter));
  }
  
  return 0;
}
