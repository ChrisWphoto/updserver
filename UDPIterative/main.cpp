/*
 Chris Walter 
 Project 2 
 
 So far I can recieve messages, print them to the console and respond 
 with a preset message. The next thing I am working on is to
 
 */

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "cipher.h"
#include <map>
#include <iostream>


#define MYPORT "8080"
#define MAXBUFLEN 100

//map that hold users
typedef std::pair<struct sockaddr_storage, socklen_t> pair_addr;
std::map<std::string, pair_addr> chatUsers;

bool userExists(std::string username, std::map<std::string, pair_addr> chatUsers){
    for(auto user : chatUsers)
    {
        if (user.first == username)
        {
            return true;
        }
    }
    return false;
}

const char* getAllUsers(std::map<std::string, pair_addr> chatUsers)
{
    std::string users;
    for (auto user : chatUsers)
    {
        users += user.first + '\n';
    }
    
    return const_cast<char*>( users.c_str() );
}

/*
 encryption function
 */
std::string crypt(std::string msg)
{
    std::string eMsg = "";
    
    int i = 0;
    while (i < msg.length())
    {
        eMsg += encr[msg[i]];
        i++;
    }
    return eMsg;
}

/*
 Decryption function
 Assumption: There will always be 2 semicolons in msg param.
 */
std::string* deCrypt(char* msg)
{
    std::string * rMsg = new std::string[3];
    if (msg[0] == '\0')
    {
        rMsg[0] = "empty reply";
        rMsg[1] = "empty reply";
        rMsg[2] = "empty reply";
    }
    //Get Rid of first 2 semi colons
    int i = 0;
    int numSemi = 0;
    while ( msg[i] != '\0' && numSemi < 1)
    {
        rMsg[0] += msg[i];
        if (msg[i] == ';')
            numSemi++;
        i++;
    }
    while ( msg[i] != '\0' && numSemi < 2)
    {
        rMsg[1] += msg[i];
        if (msg[i] == ';')
            numSemi++;
        i++;
    }
    
    
    while (msg[i] != '\0'){
        rMsg[2] += decr[msg[i]];
        i++;
    }
    return rMsg;
}


void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


/*Start Main program loop @@@@@@@@*/
int main(void)
{
    int sockfd = 0;
    struct addrinfo hints, *servinfo, *p;
    int rv;
    long numbytes;
    struct sockaddr_storage their_addr;
    char buf[MAXBUFLEN];
    socklen_t addr_len;
    char s[INET6_ADDRSTRLEN];
    
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET; //ipv4
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE; // use my IP
    
    //setup socket
    if ((rv = getaddrinfo(NULL, MYPORT, &hints, &servinfo)) != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
        return 1;
    }
    
    //bind the socket
    for(p = servinfo; p != NULL; p = p->ai_next)
    {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1)
        {
            perror("listener: socket");
            continue;
        }
        
        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1)
        {
            close(sockfd);
            perror("listener: bind");
            continue;
        }
        
        break;
    }
    //no socket could be bound
    if (p == NULL)
    {
        fprintf(stderr, "failed to bind socket\n");
        return 2;
    }
    
    freeaddrinfo(servinfo);
    
    printf("Server Running: Listening for Datagrams...\n");
    
    while(1)
    {
        //listen for messages
        addr_len = sizeof their_addr;
        if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0, (struct sockaddr *)&their_addr, &addr_len)) == -1) {
            perror("recvfrom failed");
            exit(1);
        }
        //terminate buffer
        buf[numbytes] = '\0';
        
        //print to console
        printf("Datagram recieved from %s\n",
               inet_ntop(their_addr.ss_family,
               get_in_addr((struct sockaddr *)&their_addr),s, sizeof s));
        printf("listener: packet is %ld bytes long\n", numbytes);
        printf("listener: packet contains \"%s\"\n", buf);
        
        std::string* message = deCrypt(buf);
        printf("\n---\ndecrypted: %s %s %s \n----\n", message[0].c_str(), message[1].c_str(), message[2].c_str());
        
        //get send's username
        std:size_t UsernamePos = message[2].find('\n');
        std::string theUser = message[2].substr(0,UsernamePos);
       
        
        //determine what to do with message based on message number
        switch ( std::stoi(message[1]) )
        {
                
            case 1: //potential new user
                
                //check if user exists
                if (userExists(theUser, chatUsers))
                {
                    std::cout << get_in_addr((struct sockaddr *)&chatUsers[theUser].first) <<std::endl;
                    printf("%s with IP: %s is already logged\n", theUser.c_str(),
                           inet_ntop( their_addr.ss_family, get_in_addr( (struct sockaddr *)&chatUsers[theUser].first ),s, sizeof s) );
                }
                else //user was not found, inserting new user + address, address len
                {
                    std::string welcome = "ack;" + message[0] + ';' +
                        crypt("Welcome to the group, " + theUser + '\n' + "Users Loggedin:\n" +  getAllUsers(chatUsers));
                    char* cWelcome = const_cast<char*>(welcome.c_str());
                    if ((numbytes = sendto(sockfd, cWelcome, strlen(cWelcome), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                        perror("talker: sendto");
                        exit(1);
                    }
                    
                   
                    pair_addr usersAddr = std::make_pair(their_addr, addr_len);
                    chatUsers.insert(std::make_pair(theUser, usersAddr));
                    printf("username: %s", theUser.c_str() );
                }
                
                
                break;
                
            case 2: //Forward A Message To Another Client
                
                //get name of recipient and msg
                std::string recipientNamePlusMsg = message[2].substr(UsernamePos+1, strlen( const_cast<char*>(message[2].c_str())) - UsernamePos+1);
                std::size_t msgPos = recipientNamePlusMsg.find('\n');
                std::string recipientName = recipientNamePlusMsg.substr(0, msgPos);
                std::string msgToRecipient = recipientNamePlusMsg.substr(msgPos+1);
                printf( "Msg: ' %s ' going to %s from %s \n", msgToRecipient.c_str(), recipientName.c_str(), theUser.c_str() );
                
                //Does the message recpicient exist?
                if ( userExists(recipientName, chatUsers) )
                {
                    //send ack to original sender
                    std::string ackMsg = "ack;" + message[0]; //increment by 1
                    char* cAckMsg = const_cast<char*>(ackMsg.c_str());
                    if ((numbytes = sendto(sockfd, cAckMsg, strlen(cAckMsg), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                        perror("talker: sendto");
                        exit(1);
                    }
                    
                    //forward message to other user
                    std::string forwardMsg = "Message;2;" + crypt("\nFrom: " + theUser + " to " + recipientName + " \n " + msgToRecipient);
                    char* cforwardMsg = const_cast<char*>(forwardMsg.c_str());
                    if ((numbytes = sendto(sockfd, cforwardMsg, strlen(cforwardMsg), 0, (struct sockaddr *)&chatUsers[recipientName].first, chatUsers[recipientName].second)) == -1) {
                        perror("talker: sendto");
                        exit(1);
                    }
                }
                
                else
                {
                    //send User Does Not Exist error
                    std::string errMsg = "Error;" + message[0] + ";" + crypt("User Not Logged In.");
                    char* cErrMsg = const_cast<char*>(errMsg.c_str());
                    if ((numbytes = sendto(sockfd, cErrMsg, strlen(cErrMsg), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
                        perror("talker: sendto");
                        exit(1);
                    }
                }
                
                
                //Construct a mesage fro this user
                
                //send message to user
                
                break;
                
                
        }
        fflush(stdout); //print everything before blocking call
        
        //reply to message
        std::string msg = "Ack;12345;\n";
        char* cMsg = const_cast<char*>(msg.c_str());
        if ((numbytes = sendto(sockfd, cMsg, strlen(cMsg), 0, (struct sockaddr *)&their_addr, addr_len)) == -1) {
            perror("talker: sendto");
            exit(1);
        }

        
    }
    
    //close(sockfd);
    
    return 0;
}