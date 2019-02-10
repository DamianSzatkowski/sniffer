#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

void error_handler(const char *alert)
{
	perror(alert);
	exit(1);
}

struct dhcphdr
{
	/*op - BOOTREQUEST or BOOTREPLY*/
	uint8_t op;
	/*Hardware address type*/
	uint8_t htype;
	/*Hardware address length*/
	uint8_t hlen;
	/*Number of hops from server*/
	uint8_t hops;
	/*Transaction ID*/
	uint32_t xid;
	/*Seconds since start of acquisition*/
	uint16_t secs;
	/*Flags*/
	uint16_t flags;
	/*Client IP address - this is filled in if the client already has an
	IP address assigned and can respond to ARP requests*/
	struct in_addr ciaddr;
	/*Your IP address - this is the address assigned by the server to the
	client*/
	struct in_addr yiaddr;
	/*Server IP address - this is the IP address of the next server to be
	used in the boot process*/
	struct in_addr siaddr;
	/*Gateway IP address - this is the IP address of the DHCP relay
	agent, if any*/
	struct in_addr giaddr;
	/*Client hardware address*/
	uint8_t chaddr[16];
	/*Server host name - NULL terminated - this field may be overidden
	and contain DHCP options*/
	char sname[64];
	/*Boot file name*/
	char file[128];
	/*DHCP magic cookie - must have the value DHCP_MAGIC_COOKIE*/
	uint32_t magic;
	/*DHCP options - variable length; extends to the end of the packet.
	Minimum lenth (for the sake of sanity) is 1, to allow for a single
	DHCP_END tag*/
	uint8_t options[0];
};

void prot_dhcp(unsigned char *buff)
{
	struct dhcphdr *dhcp;
	char IPaddress[INET_ADDRSTRLEN]; /*zmienna potrzebna nam pozniej do inet_ntop*/
	dhcp = (struct dhcphdr *)buff;

	/*wypisywanie informacji*/
	printf("Operacja: %u\n", dhcp->op);
	if( (dhcp->op) == 1 )
		printf("Operacja - BOOTREQUEST\n");
	else if( (dhcp->op) == 2 )
		printf("Operacja - BOOTREPLY\n");

	printf("Typ adresu sprzetowego: %u\n", dhcp->htype);
	printf("Dlugosc adresu sprzetowego: %u\n", dhcp->hlen);
	printf("Liczba skokow \"hops\": %u\n", dhcp->hops);
	printf("ID transakcji: %u\n", ntohl(dhcp->xid));
	printf("Nazwa pliku rozruchowego \"boot file\" name: %s\n", dhcp->file);

	if( (inet_ntop(AF_INET, &(dhcp->ciaddr), IPaddress, INET_ADDRSTRLEN)) == NULL )
		error_handler("inet_ntop");
	printf("IP klienta (opcjonalnie): %s\n", IPaddress);

	if( (inet_ntop(AF_INET, &(dhcp->yiaddr), IPaddress, INET_ADDRSTRLEN)) == NULL )
		error_handler("inet_ntop");
	printf("Adres przypisany klientowi przez serwer: %s\n", IPaddress);

	if( (inet_ntop(AF_INET, &(dhcp->siaddr), IPaddress, INET_ADDRSTRLEN)) == NULL )
		error_handler("inet_ntop");
	printf("Adres nastepnego serwera: %s\n", IPaddress);

	if( (inet_ntop(AF_INET, &(dhcp->giaddr), IPaddress, INET_ADDRSTRLEN)) == NULL )
		error_handler("inet_ntop");
	printf("Adres bramy (opcjonalnie): %s\n", IPaddress);
}

void prot_tcp(unsigned char *buff)
{
	struct tcphdr *tcp;
	tcp = (struct tcphdr *)buff;

	printf("\n*****Protokol TCP*****\n");

	printf("Port zrodlowy: %u\n", ntohs(tcp->th_sport));
	printf("Port docelowy: %u\n", ntohs(tcp->th_dport));
	printf("Suma kontrolna: %u\n", ntohs(tcp->th_sum));
	printf("Numer sekwencji: %u\n", ntohl(tcp->th_seq));
	printf("Spodziewany numer sekwencji nastepnego oktetu: %u\n", ntohl(tcp->th_ack));

	/*sprawdzamy porty - zrodlowy i docelowy*/
	if( ntohs(tcp->th_sport)==80 )
		printf("\n*****Protokol HTTP*****\n");
	if( ntohs(tcp->th_dport)==80 )
		printf("\n*****Protokol HTTP*****\n");

}

void prot_udp(unsigned char *buff)
{
	struct udphdr *udp;

	udp = (struct udphdr *)buff;

	printf("\n*****Protokol UDP*****\n");

	printf("Port zrodlowy: %u\n", ntohs(udp->uh_sport));
	printf("Port docelowy: %u\n", ntohs(udp->uh_dport));
	printf("Dlugosc UDP: %d\n", ntohs(udp->uh_ulen));
	printf("Suma kontrolna UDP: %u\n", ntohs(udp->uh_sum));

	/*sprawdzamy porty*/
	/*port 67 - od klienta do serwera, port 68 odwrotnie*/
	if( ntohs(udp->dest)==67 )
	{
		printf("\n*****Protokol DHCP - serwer*****\n");
		prot_dhcp(buff + sizeof(struct udphdr));
	}
	else if( ntohs(udp->dest)==68 )
	{
		printf("\n*****Protokol DHCP - klient*****\n");
		prot_dhcp(buff + sizeof(struct udphdr));
	}

}

void prot_icmp(unsigned char *buff)
{
	struct icmphdr *icmp;
	struct in_addr inaddr; /*struktura do inet_ntop*/

	icmp = (struct icmphdr *)buff;

	/*zmienna, w ktorej bedzie przechowywany adres bramy*/
	char gateway[INET_ADDRSTRLEN];

	inaddr.s_addr = (icmp->un).gateway;

	if( (inet_ntop(AF_INET, &inaddr, gateway, INET_ADDRSTRLEN)) == NULL )
		error_handler("inet_ntop");

	printf("\n*****Protokol ICMP*****\n");

	printf("Typ wiadomosci: %u\n", icmp->type);
	printf("Sub-typ/code: %u\n", icmp->code);
	printf("Suma kontrolna: %u\n", ntohs(icmp->checksum));
	printf("ID: %u\n", ntohs((icmp->un).echo.id));
	printf("Numer sekwencji: %u\n", ntohs((icmp->un).echo.sequence));
	printf("Adres bramy: %s\n", gateway);
}

void prot_icmp6(unsigned char *buff)
{
	struct icmp6_hdr *icmp6;
	icmp6 = (struct icmp6_hdr *)buff;

	printf("Typ: %u", icmp6->icmp6_type);
	printf("Kod/code : %u", icmp6->icmp6_code);
	printf("Suma kontrolna: %u", ntohs(icmp6->icmp6_cksum));
}

void prot_arp(unsigned char *buff)
{
	struct ether_arp *arp;

	printf("\n*****Protokol ARP*****\n");

	arp = (struct ether_arp *)buff;

	printf("Adres MAC nadawcy: %02x:%02x:%02x:%02x:%02x:%02x\n",
				arp->arp_sha[0],
				arp->arp_sha[1],
				arp->arp_sha[2],
				arp->arp_sha[3],
				arp->arp_sha[4],
				arp->arp_sha[5]);
	printf("Adres MAC odbiorcy: %02x:%02x:%02x:%02x:%02x:%02x\n",
				arp->arp_tha[0],
				arp->arp_tha[1],
				arp->arp_tha[2],
				arp->arp_tha[3],
				arp->arp_tha[4],
				arp->arp_tha[5]);


	printf("Adres IP nadawcy: %d.%d.%d.%d\n",
				arp->arp_spa[0],
				arp->arp_spa[1],
				arp->arp_spa[2],
				arp->arp_spa[3]);
	printf("Adres IP odbiorcy: %d.%d.%d.%d\n",
				arp->arp_tpa[0],
				arp->arp_tpa[1],
				arp->arp_tpa[2],
				arp->arp_tpa[3]);

	

}

void prot_ip4(unsigned char *buff)
{
	struct ip *ip4;
	char src[INET_ADDRSTRLEN]; /*zmienna - adres nadawcy*/
	char dst[INET_ADDRSTRLEN]; /*zmienna - adres odbiorcy*/

	printf("\n*****Protokol IPv4*****\n");

	ip4 = (struct ip *)buff;
	
	if( (inet_ntop(AF_INET, &(ip4->ip_src), src, INET_ADDRSTRLEN)) == NULL )
		error_handler("inet_ntop");
	printf("Adres IP nadawcy: %s\n", src);

	if( (inet_ntop(AF_INET, &(ip4->ip_dst), dst, INET_ADDRSTRLEN)) == NULL )
		error_handler("inet_ntop");
	printf("Adres IP odbiorcy: %s\n", dst);


	printf("Wersja: %u\n", ip4->ip_v);
	printf("TTL: %u\n", ip4->ip_ttl);
	printf("Dlugosc pakietu IP: %u\n", ntohs(ip4->ip_len));
	printf("Suma kontrolna: %u\n", ntohs(ip4->ip_sum));

	/*sprawdzamy nastepny protokol*/
	/*zmienna ip_hl podawana w 32 bitowych slowach*/
	if(ip4->ip_p == 0x06)
	{
		prot_tcp(buff + ((ip4->ip_hl)*4));
	}
	else if(ip4->ip_p == 0x11)
	{

		prot_udp(buff + ((ip4->ip_hl)*4));
	}
	else if (ip4->ip_p == 0x01)
	{
		prot_icmp(buff + ((ip4->ip_hl)*4));
	}

}

void prot_ip6(unsigned char *buff)
{
	struct ip6_hdr *ip6;
	char src[INET6_ADDRSTRLEN]; /*zmienna - adres nadawcy*/
	char dst[INET6_ADDRSTRLEN]; /*zmienna - adres odbiorcy*/

	printf("\n*****Protokol IPv6*****\n");

	ip6 = (struct ip6_hdr *)buff;

	if( (inet_ntop(AF_INET6, &(ip6->ip6_src), src, INET6_ADDRSTRLEN)) == NULL )
		error_handler("inet_ntop");
	if( (inet_ntop(AF_INET6, &(ip6->ip6_dst), dst, INET6_ADDRSTRLEN)) == NULL )
		error_handler("inet_ntop");

	printf("Adres nadawcy: %s\n", src);
	printf("Adres odbiorcy: %s\n", dst);
	printf("Hop limit(TTL): %u\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim);
	printf("Dlugosc Payload'a: %u\n", ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen));
	printf("Numer nastepnego protokolu: %u\n", ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt);

	if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 0x06)
	{
		prot_tcp(buff + sizeof(struct ip6_hdr));
	}
	else if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 0x11)
	{
		prot_udp(buff + sizeof(struct ip6_hdr));
	}
	else if(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == 0x01)
	{
		prot_icmp6(buff + sizeof(struct ip6_hdr));
	}
}

void prot_ethernet(unsigned char *buff)
{
	struct ether_header *ether;

	ether = (struct ether_header *)buff;

	printf("\n*****Protokol Ethernet*****\n");

	printf("Adres MAC nadawcy: %02x:%02x:%02x:%02x:%02x:%02x\n",
				ether->ether_shost[0],
				ether->ether_shost[1],
				ether->ether_shost[2],
				ether->ether_shost[3],
				ether->ether_shost[4],
				ether->ether_shost[5]);
	printf("Adres MAC odbiorcy: %02x:%02x:%02x:%02x:%02x:%02x\n",
				ether->ether_dhost[0],
				ether->ether_dhost[1],
				ether->ether_dhost[2],
				ether->ether_dhost[3],
				ether->ether_dhost[4],
				ether->ether_dhost[5]);

	/*sprawdzamy nastepny protokol*/
	switch( ntohs(ether->ether_type) )
	{
		case 0x0806:
			prot_arp(buff + sizeof(struct ether_header));
			break;
		
		case 0x0800:
			prot_ip4(buff + sizeof(struct ether_header));
			break;

		case 0x86DD:
			prot_ip6(buff + sizeof(struct ether_header));
			break;

		default:
			printf("Nie rozpoznano protokolu!\n");
			break;
	}


}

int main(int argc, char *argv[])
{
	/*deskryptor na socket*/
	int sd;
	/*struktura uzyta przez nas do przejscia w tryb mieszany*/
	/*struct ifreq ifr;*/
	struct sockaddr saddr;
	socklen_t saddr_size;
	ssize_t data_size;

	unsigned char *buff = (unsigned char *)malloc(65536);
	memset(buff, 0, 65536);

	/*uzyskujemy deskryptor do gniazda*/
	if( (sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))==-1 )
		error_handler("blad socket");

	/*przechodzimy w tryb mieszany*/
	/*strncpy( (char *)ifr.ifr_name, argv[1], IF_NAMESIZE );
	strcpy(ifr.ifr_name, argv[1]);
	ifr.ifr_flags |= IFF_PROMISC;

	if( ioctl(sd, SIOCSIFFLAGS, &ifr)!=0 )
		error_handler("blad ioctl");*/


	while(1)
	{
		saddr_size = sizeof(saddr);

		if( (data_size = recvfrom(sd, buff, 65536, 0, &saddr, &saddr_size))==-1 )
			error_handler("recvfrom");

		prot_ethernet(buff);
	}

	if( (close(sd)) == -1 )
		error_handler("close");

	free(buff);

	return 0;
}
