

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

#define CHECKSUM_PRESENT '\x80'
#define ROUTING_PRESENT '\x40'
#define KEY_PRESENT '\x20'
#define SEQUENCE_PRESENT '\x10'


typedef struct frame_s {
// A data type to store the bits we need to construct a simple frame from a more complex one.
	char 		*ether;
	char		*payload;
	unsigned int	plen;
	char 		etype[2];
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
} params_t;


