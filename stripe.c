

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stripe.h"

#define SWVERSION "v0.2 alpha"
#define SWRELEASEDATE "December 2014"

// STRIPE (STRIP Encapsulation) attempts to peel away layers of VLAN and MPLS tags,
// PPPoE headers, L2TP and GTP leaving plain untagged payload over Ethernet. The resulting
// plain frames are then saved in a pcap file which can then be fed to applications that
// are not able to deal with the additional headers. 
// Written by Foeh Mannay
// Please refer to http://networkbodges.blogspot.com for more information about this tool.
// This software is released under the Modified BSD license.

params_t *parseParams(int argc, char *argv[]){
	// Returns a struct with various parameters or NULL if invalid
	unsigned int i = 1;
	params_t *parameters = (params_t*)malloc(sizeof(params_t));
	if(parameters == NULL) return(NULL);

	// There must be 4 parameters
	if(argc != 5) return(NULL);

	// Set some defaults
	parameters->infile = NULL;
	parameters->outfile = NULL;

	// Look for the various flags, then store the corresponding value
	while(i < argc){
		if(strcmp(argv[i],"-r") == 0){
			parameters->infile = argv[++i];
			i++;
			continue;
		}
		if(strcmp(argv[i],"-w") == 0){
			parameters->outfile = argv[++i];
			i++;
			continue;
		}
		// If we get any unrecognised parameters just fail
		return(NULL);
	}

	// If the input files still aren't set, bomb
	if((parameters->infile == NULL) || (parameters->outfile == NULL)) return(NULL);

	return(parameters);
}

frame_t *decap(char *data, unsigned int length, char type, frame_t *frame){
// The decap() function takes in a  pointer to a (partial) frame, the size of the 
// data, a hint indicating the encap type and a frame template and attempts to
// fill the frame template with the required details.
	int vlen = 0;
	int pos = 0;

	// Some sanity checks
	if(data == NULL) return(NULL);

	// Based on current encap type, try to determine what the next encap type will be
	//printf("Parsing type %u, length %u.\n", type, length);
	switch(type){
		case ETHERNET:
			if(length < 14) return(NULL);
			
			// Populate the ethernet portion then copy the EtherType
			frame->ether = data;
			memcpy(frame->etype, data+12, 2);
			frame->plen = length - 14;
			frame->payload = data + 14;
			
			// VLAN tag next?
			if(memcmp(data+12, "\x81\x00", 2) == 0 || memcmp(data+12, "\x91\x00", 2) == 0){
				return(decap(data + 14, length - 14, VLAN, frame));
			}
			// MPLS tag next?
			if(memcmp(data+12, "\x88\x47", 2) == 0){
				return(decap(data + 14, length - 14, MPLS, frame));
			}
			// PPPoE session data next?
			if(memcmp(data+12, "\x88\x64", 2) == 0){
				return(decap(data + 14, length - 14, PPPoE, frame));
			}
			// IP next?
			if(memcmp(data+12, "\x08\x00",2) == 0){
				return(decap(data + 14, length - 14, IPv4, frame));
			}
			// Something else next?
            		return(decap(data + 14, length - 14, UNKNOWN, frame));
			break;
		case VLAN:
			if(length < 4) return(NULL);
			frame->plen = length - 4;
			frame->payload = data + 4;
			memcpy(frame->etype, data+2, 2);
			
			// Just skim over VLANs and determine the next encap type from the EtherType
			// VLAN tag next?
			if((memcmp(data+2, "\x81\x00", 2) == 0) || (memcmp(data+2, "\x91\x00",2) == 0)){
				return(decap(data + 4, length - 4, VLAN, frame));
			}
			// MPLS tag next?
			if(memcmp(data+2, "\x88\x47", 2) == 0){
				return(decap(data + 4, length - 4, MPLS, frame));
			}
			// PPPoE session data next?
			if(memcmp(data+2, "\x88\x64", 2) == 0){
				return(decap(data + 4, length - 4, PPPoE, frame));
			}
			// IP next?
			if(memcmp(data+2, "\x08\x00", 2) == 0){
				return(decap(data + 4, length - 4, IPv4, frame));
			}
			// Something else next?
			return(decap(data + 4, length - 4, UNKNOWN, frame));
			break;
		case MPLS:
			if(length < 4) return(NULL);
			frame->plen = length - 4;
			frame->payload = data + 4;
			
			// Check bottom of stack bit to decide whether to keep stripping MPLS or try for Ethernet
			if((data[2] & '\x01') == 0){
				return(decap(data + 4, length - 4, MPLS, frame));	// Not BOS, more MPLS
			}

			if((data[4] & '\xf0') == '\x40'){						// IPv4 (guess)
				memcpy(frame->etype, "\x08\x00", 2);
				return(decap(data + 4, length - 4, IPv4, frame));
			} else if((data[4] & '\xf0') == '\x60'){				// IPv6 (guess)
				memcpy(frame->etype, "\x86\xdd", 2);
				return(decap(data + 4, length - 4, UNKNOWN, frame));
			} else {
				if(memcmp(data + 4, "\x00\x00\x00\x00", 4) == 0){
					// guessing ethernet control word present... 
					return(decap(data + 8, length - 8, ETHERNET, frame));	
				} else {
					return(decap(data + 4, length - 4, ETHERNET, frame));	// Ethernet (guess)
				}
			}
		break;
		case PPPoE:
			// Only a PPP header can follow a PPPoE session header
			if(length < 6) return(NULL);
			frame->payload = data;
			frame->plen = length;
			return(decap(data + 6, length - 6, PPP, frame));
		break;
		case PPP:
			// Should be IPv4 or IPv6 behind this, otherwise bail.
			if(length < 2) return(NULL);

			if(memcmp(data, "\x00\x21", 2) == 0){				// IPv4
				memcpy(frame->etype, "\x08\x00", 2);
				frame->plen = length - 2;
				frame->payload = data + 2;
				return(decap(data + 2, length - 2, IPv4, frame));
			} else if(memcmp(data, "\x00\x57", 2) == 0){		// IPv6
				memcpy(frame->etype, "\x86\xdd", 2);
				frame->plen = length - 2;
				frame->payload = data + 2;
				return(decap(data + 2, length - 2, UNKNOWN, frame));
			}
			else return(frame);
		break;
		case IPv4:
			// If the protocol is IPv4 we may find some GRE / L2TP encap
			if(length < 20) return(NULL);
			if(length < 4 * (data[0] & 15)) return(NULL);
            
            frame->payload = data;
            frame->plen = length;
			
			if(data[9] == '\x11'){			// UDP
				return(decap(data + (4 * (data[0] & 15)), length - (4 * (unsigned char)(data[0] & 15)), UDP, frame));
			} else if(data[9] == '\x2f'){	// GRE
				return(decap(data + (4 * (data[0] & 15)), length - (4 * (unsigned char)(data[0] & 15)), GRE, frame));
            } else {
            	return(frame);
            }

		break;
		case GRE:
			// GRE uses normal ethertypes to describe its payload, makes life easy.
			
			// If source routing is present in the GRE header, bail out
			if(((unsigned char)data[0] & ROUTING_PRESENT) != 0) return(frame);
			
			// Adjust the offset according to what's in the GRE header
			if(((unsigned char)data[0] & CHECKSUM_PRESENT) != 0) pos += 4;
			if(((unsigned char)data[0] & KEY_PRESENT) != 0) pos += 4;
			if(((unsigned char)data[0] & SEQUENCE_PRESENT) != 0) pos += 4;
			
			if(length < pos + 4){
				return(frame);
			} else {
				// Valid to decode
				frame->plen = length - (pos + 4);
				frame->payload = data + pos + 4;
				memcpy(frame->etype, data + 2, 2);
			
				// VLAN tag next?
				if(memcmp(data+2, "\x81\x00", 2) == 0 || memcmp(data+2, "\x91\x00", 2) == 0){
					return(decap(frame->payload, frame->plen, VLAN, frame));
				}
				// MPLS tag next?
				if(memcmp(data+2, "\x88\x47", 2) == 0){
					return(decap(frame->payload, frame->plen, MPLS, frame));
				}
				// PPPoE session data next?
				if(memcmp(data+2, "\x88\x64", 2) == 0){
					return(decap(frame->payload, frame->plen, PPPoE, frame));
				}
				// IP next?
				if(memcmp(data+2, "\x08\x00",2) == 0){
				return(decap(frame->payload, frame->plen, IPv4, frame));
				}
				// Something else next?
    	        return(frame);
            }
		break;
		case UDP:
			// If the protocol is UDP, check for L2TP port numbers
			if(length < 8) return(NULL);
			
			if(memcmp(data + 2, "\x06\xa5", 2) == 0){		// L2TP
				return(decap(data + 8, length - 8, L2TP, frame));
			} else if(memcmp(data + 2, "\x08\x68", 2) == 0){// GTP
				return(decap(data + 8, length - 8, GTP, frame));
			} else return(frame);
		break;
		case L2TP:
			// If we get an L2TP data packet, deal with the payload.
			if(length < 12) return(NULL);
			if(((data[1] & '\x0f') != '\x02') || ((data[0] & '\xcb') != '\xc8')) return(NULL);
			vlen = (256*(unsigned char)data[2])+(unsigned char)data[3];
			if(vlen > length) return(NULL);	// If the header says length > remaining data, bail out
			
			return(decap(data + 12, vlen - 12, L2AVP, frame));
		break;
		case L2AVP:
			// Work through the L2TP AVPs to try and gather auths.
			if(length < 6){
				printf("short?\n");
				return(frame);
			} else return(frame);
			vlen = (256 * ((unsigned char)data[0] & 3)) + (unsigned char)data[1];
			if(vlen > length) return(NULL);
			
			// If this isn't a reserved AVP, we're not interested.
			if(memcmp(data + 2, "\x00\x00\x00", 3) != 0) return(decap(data + vlen, length - vlen, L2AVP, frame));
			
			switch(data[5]){
				case '\x00':		// Control message type
					// CHAP should only be in an ICCN message, so abandon anything else
					if(memcmp(data + 6, "\x00\x0c", 2) != 0){
						return(NULL);
					}
				break;
				case '\x1e':		// Username
				break;
				case '\x1f':		// CHAP challenge data
				break;
				case '\x20':		// Authentication ID
				break;
				case '\x21':		// CHAP response data
				break;	
			}
			return(decap(data + vlen, length - vlen, L2AVP, frame));
		break;
		case GTP:
			// If we get a GTP data packet, deal with the payload.
			if(length < 28) return(frame);
			
			// If frame is not a GTP U frame then don't bother decap-ing it
			if(((data[0] & '\xe0') != '\x20') || (data[1] != '\xff')) return(frame);
			
			vlen = (256*(unsigned char)data[2])+(unsigned char)data[3];

			if((data[0] & '\x07') != 0) {						// Long header
				if(vlen > (length - 8)) return(NULL);			// If the header says length > remaining data, bail out
				
				pos = 12;
				if(((unsigned char)data[0] & '\x04') != 0) {
					while((unsigned char)data[pos-1] != 0){		// Shave off any extension headers
						if(((unsigned char)data[pos]) == '\x00') return(NULL);	// avoid getting stuck for zero length extension headers
						pos += (((unsigned char)data[pos]) * 4);
						if(pos > vlen) return(NULL);			// Check we're not over-reading
					}
				}
			} else {											// Short header
				if(vlen > (length - 8)) return(NULL);			// If the header says length > remaining data, bail out
				pos = 8;
			}
			
			// Parsed OK, update frame template and parse IPv4
			frame->plen = length - pos;
			frame->payload = data + pos;
			memcpy(frame->etype, "\x08\x00", 2);
			return(decap(data + pos, vlen - pos, IPv4, frame));
			
		break;
		case UNKNOWN:
			// Non-encapsulating payload, just return
			frame->plen = length;
			frame->payload = data;
			return(frame);
		break;
	}
	return(NULL);
}

int parse_pcap(FILE *capfile, FILE *outfile){
	char 				*memblock = NULL;
	frame_t				*frame = NULL,
						*decapped = NULL;
	guint32				caplen = 0;
	int					decapcount = 0;
	pcaprec_hdr_t		*rechdr = NULL;
	
	printf("\nParsing capfile...\n");
	
	// Start parsing the capture file:
	rewind(capfile);
	clearerr(capfile);
	memblock = (char*)malloc(sizeof(pcap_hdr_t));
	if(memblock == NULL){
		printf("Insufficient memory to load capture header.\n");
		return(0);
	}
	// Read the pcap header
	if(fread (memblock, 1, sizeof(pcap_hdr_t), capfile) != sizeof(pcap_hdr_t)){
		printf("Truncated capture file header - aborting.\n");
		if(memblock != NULL) free(memblock);
		return(0);
	}
	// Verify the magic number in the header indicates a pcap file
	if(((pcap_hdr_t*)memblock)->magic_number != 2712847316){
		printf("\nError!\nThis is not a valid pcap file. If it has been saved as pcap-ng\nconsider converting it to original pcap format with tshark or similar.\n");
		if(memblock != NULL) free(memblock); 
		return(0);
	}
	// Create the frame template used in the decap process
	frame = malloc(sizeof(frame_t));
	if(frame == 0){
		printf("Error: unable to allocate memory for frame template!\n");
		return(0);
	}
	// Allocate memory for the PCAP record header
	rechdr = (pcaprec_hdr_t*)malloc(sizeof(pcaprec_hdr_t));
	if(rechdr == NULL){
		printf("Error: unable to allocate memory for pcap record header!\n");
		return(0);
	}
	// Clone the input file's header
	rewind(outfile);
	clearerr(outfile);
	if(fwrite(memblock, 1, sizeof(pcap_hdr_t), outfile) != sizeof(pcap_hdr_t)){
		printf("Error: unable to write pcap header to output file!\n");
		return(0);
	}

	// Read in each frame.
	while((!feof(capfile)) & (!ferror(capfile))) {
		free(memblock);
		// Get the packet record header and examine it for the packet size
		caplen = fread (rechdr, 1, sizeof(pcaprec_hdr_t), capfile);
		if(caplen != sizeof(pcaprec_hdr_t)){
			if(caplen > 0) printf("Error: Truncated pcap file reading record header, %u/%lu!\n", caplen, sizeof(pcaprec_hdr_t));
			break;
		}
		caplen = rechdr->incl_len;
		
		memblock = malloc(caplen);
		if(memblock == NULL){
			printf("Error: Could not allocate memory for pcap record header!\n");
			return(decapcount);
		}
		// Get the actual packet data and attempt to parse it
		if(fread (memblock, 1, caplen, capfile) != caplen){
			printf("Error: Truncated pcap file reading capture!\n");
			break;
		}
		
		// Attempt to decapsulate the frame
		frame->ether = NULL;
		memcpy(frame->etype, "\x00\x00", 2);
		frame->payload = NULL;
		frame->plen = 0;
		decapped = decap(memblock, caplen, ETHERNET, frame);
		// Write the decapsulated frame to the output file
		
		if(decapped != NULL){
			decapcount++;

			if(decapped->plen < 46) { // pad undersized frames!
				rechdr->incl_len = 60;
				rechdr->orig_len = 60;
			} else {
				rechdr->incl_len = decapped->plen+14;
				rechdr->orig_len = decapped->plen+14;
			}
						
			if(fwrite(rechdr, 1, sizeof(pcaprec_hdr_t), outfile) != sizeof(pcaprec_hdr_t)){
				printf("Error: unable to write pcap record header to output file!\n");
				return(0);
			}
			if(fwrite(decapped->ether, 1, 12, outfile) != 12){
				printf("Error: unable to write frame to output pcap file\n");
				return(0);
			}
			if(fwrite(decapped->etype, 1, 2, outfile) != 2){
				printf("Error: unable to write frame to output pcap file\n");
				return(0);
			}
			if(fwrite(decapped->payload, 1, decapped->plen, outfile) != decapped->plen){
				printf("Error: unable to write frame to output pcap file\n");
				return(0);
			}
			if(decapped->plen < 46) { // pad undersized frames!
				if(fwrite(PADDING, 1, (46 - frame->plen), outfile) != (46 - decapped->plen)){
					printf("Error: unable to write frame padding to output pcap file\n");
					return(0);
				}
			}
		}
	}
	if(rechdr != NULL) free(rechdr);

	return(decapcount);
}

int main(int argc, char *argv[]){
// The main function basically just calls other functions to do the work.
	params_t			*parameters = NULL;
	FILE				*infile = NULL,
						*outfile = NULL;
	
	// Parse our command line parameters and verify they are usable. If not, show help.
	parameters = parseParams(argc, argv);
	if(parameters == NULL){
		printf("stripe: a utility to remove VLAN tags, MPLS shims, PPPoE, L2TP headers,\n");
		printf("etc. from the frames in a PCAP file and return untagged IP over Ethernet.\n");
		printf("Version %s, %s\n\n", SWVERSION, SWRELEASEDATE);
		printf("Usage:\n");
		printf("%s -r inputcapfile -w outputcapfile\n\n",argv[0]);
		printf("Where inputcapfile is a tcpdump-style .cap file containing encapsulated IP \n");
		printf("outputcapfile is the file where the decapsulated IP will be saved\n");
		return(1);
	}
	
	// Attempt to open the capture file and word list:
	infile = fopen(parameters->infile,"rb");
	if (infile == NULL) {
		printf("\nError!\nUnable to open input capture file!\n");
		return(1);
	}
	outfile = fopen(parameters->outfile, "wb");
	if(outfile == NULL){
		printf("Error - could not open output file!\n");
		return(1);
	}
	
	printf("\n%d frames processed.\n", parse_pcap(infile, outfile));

	fclose(infile);
	fclose(outfile);
	
	return(0);
}


