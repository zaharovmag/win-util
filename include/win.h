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


#define MAX_LEN 1000

struct ace {
  char ap[MAX_LEN];
  struct ace * next;
};

struct acl {
  char owner[MAX_LEN];
  char group[MAX_LEN];
  struct ace * list_ace;
};

#define ACL_PREFIX       "-:"
#define ACL_POSTFIX      ":---"
#define ACL_USER_POS     0
#define ACL_READ_POS     1
#define ACL_WRITE_POS    2
#define ACL_EXECUTE_POS  3
#define ACL_USER         'u'
#define ACL_GROUP        'g'
#define ACL_READ         'r'
#define ACL_WRITE        'w'
#define ACL_EXECUTE      'x'


int get_file_acl(PSECURITY_DESCRIPTOR pSD,struct acl * acl);
int get_account_sid(PSID pSid,char * account,size_t acclen,
		    SID_NAME_USE * peUse);
int get_ace(PACL pAcl,struct acl * acl,SID_NAME_USE * peUse);
int get_textual_sid(PSID pSid,char * buf,size_t len);
