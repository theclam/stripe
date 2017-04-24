

#define CHAP_NONE '\x00'
#define CHAP_CHALLENGE '\x01'
#define CHAP_RESPONSE '\x02'
#define CHAP_BOTH '\x03'
#define ETHERNET '\x01'
#define VLAN '\x02'
#define MPLS '\x03'
#define PPPoE '\x04'
#define PPP '\x05'
#define CHAP '\x06'
#define IPv4 '\x07'
#define UDP '\x08'
#define RADIUS '\x09'
#define RADAVP '\x0a'
#define L2TP '\x0b'
#define L2AVP '\x0c'
#define OSPFv2 '\x0d'
#define OSPF_MD5 '\x0e'
#define TCP '\x0f'
#define IP_MD5 '\x10'
#define UNKNOWN '\x11'
#define GRE '\x12'
#define GTP '\x13'
#define VXLAN '\x14'
#define SLL '\x15'
#define IPv6 '\x16'

#define CHECKSUM_PRESENT '\x80'
#define ROUTING_PRESENT '\x40'
#define KEY_PRESENT '\x20'
#define SEQUENCE_PRESENT '\x10'

#define MOREFRAGS '\x20'

#define NODEFRAG '\x01'
#define DEBUGGING '\x02'


// pcap constants
// Ethernet (10Mb)
#define DLT_EN10MB  1
// Linux cooked sockets.
#define DLT_LINUX_SLL 113

// if_ether.h constants
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100          /* 802.1Q VLAN Extended Header  */
#endif
#ifndef ETH_P_QINQ1
#define ETH_P_QINQ1 0x9100    /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#endif
#ifndef ETH_P_MPLS_UC
#define ETH_P_MPLS_UC 0x8847    /* MPLS Unicast traffic   */
#endif
#ifndef ETH_P_PPP_SES
#define ETH_P_PPP_SES 0x8864    /* PPPoE session messages */
#endif
#ifndef ETH_P_IP
#define ETH_P_IP  0x0800    /* Internet Protocol packet */
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6  0x86DD    /* IPv6 over bluebook   */
#endif


typedef struct frame_s {
// A data type to store the bits we need to construct a simple frame from a more complex one.
	char 		*l2;
	char		*payload;
	unsigned int	plen;
	char 		etype[2];
	int			fragment;
} frame_t;

typedef unsigned int guint32;
typedef unsigned short guint16;
typedef signed int gint32;
typedef struct pcap_hdr_s {
        guint32 magic_number;   /* magic number */
        guint16 version_major;  /* major version number */
        guint16 version_minor;  /* minor version number */
        gint32  thiszone;       /* GMT to local correction */
        guint32 sigfigs;        /* accuracy of timestamps */
        guint32 snaplen;        /* max length of captured packets, in octets */
        guint32 network;        /* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
        guint32 ts_sec;         /* timestamp seconds */
        guint32 ts_usec;        /* timestamp microseconds */
        guint32 incl_len;       /* number of octets of packet saved in file */
        guint32 orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct params_s {
	char *infile;
	char *outfile;
	char modifiers;
} params_t;

typedef struct fragment_detail_s {
	guint16 					start;
	guint16 					end;
	char						more;
	char						*data;
} fragment_detail_t;

typedef struct frag_hole_s {
	guint16		start;
	guint16		end;
	struct frag_hole_s	*prev;
	struct frag_hole_s	*next;
} frag_hole_t;

typedef struct fragment_list_s {
	char 					*ipinfo;
	char					*header;
	char					*data;
	struct fragment_list_s	*next;
	guint16					size;
	frag_hole_t 			*holes;
} fragment_list_t;

