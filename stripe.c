

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "stripe.h"
#include "stripe-defrag.h"

#define SWVERSION "v0.3c"
#define SWRELEASEDATE "January 2016"

// STRIPE (STRIP Encapsulation) attempts to peel away layers of VLAN and MPLS tags, PPPoE
// L2TP, GTP and VXLAN headers leaving plain untagged payload over Ethernet. The resulting
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

	// There must be 4 or 5 parameters
	if((argc < 5) || (argc > 6)) return(NULL);

	// Set some defaults
	parameters->infile = NULL;
	parameters->outfile = NULL;
	parameters->modifiers = 0;

	// Look for the various flags, then store the corresponding value
	while(i < argc){
		if((strcmp(argv[i],"-r") == 0) && (i < argc - 1)){
			parameters->infile = argv[++i];
			i++;
			continue;
		}
		if((strcmp(argv[i],"-w") == 0) && (i < argc - 1)){
			parameters->outfile = argv[++i];
			i++;
			continue;
		}
		if(strcmp(argv[i],"-f") == 0){
			parameters->modifiers = parameters->modifiers | NODEFRAG;
			i++;
			continue;
		}
		if(strcmp(argv[i],"-v") == 0){
			parameters->modifiers = parameters->modifiers | DEBUGGING;
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

frame_t *decap(char *data, unsigned int length, char type, frame_t *frame, int modifiers){
// The decap() function takes in a pointer to a (partial) frame, the size of the
// data, a hint indicating the encap type and a frame template and attempts to
// fill the frame template with the required details.
	int vlen = 0;
	int pos = 0;
	int min_length = -1;
	int ethertype_offset = -1;
	int ethertype = -1;
	int l2_header_length = -1;
	int header_length = -1;
	int dst_port = -1;

	// Some sanity checks
	if(data == NULL) return(NULL);

	if((modifiers & DEBUGGING) == DEBUGGING){
		printf("decap() called on %u bytes as type %u.\n", length, type);
		if(length > 13) hexdump(data, 14);
		printf("\n\n");
	}

	// Based on current encap type, try to determine what the next encap type will be
	switch(type){
		case ETHERNET:
		case SLL:
			if(type == ETHERNET) {
				min_length = 14;
				ethertype_offset = 12;
				l2_header_length = 14;
			} else if(type == SLL) {
				min_length = 16;
				ethertype_offset = 14;
				l2_header_length = 16;
			}

			if(length < min_length) return(NULL);

			// Populate the L2 portion then copy the EtherType
			frame->l2 = data;
			memcpy(frame->etype, data+ethertype_offset, 2);
			ethertype = ntohs(*(uint16_t *)(data+ethertype_offset));
			frame->plen = length - l2_header_length;
			frame->payload = data + l2_header_length;

			// VLAN tag next?
			if(ethertype == ETH_P_8021Q || ethertype == ETH_P_QINQ1){
				return(decap(data + l2_header_length, length - l2_header_length, VLAN, frame, modifiers));
			}
			// MPLS tag next?
			if(ethertype == ETH_P_MPLS_UC){
				return(decap(data + l2_header_length, length - l2_header_length, MPLS, frame, modifiers));
			}
			// PPPoE session data next?
			if(ethertype == ETH_P_PPP_SES){
				return(decap(data + l2_header_length, length - l2_header_length, PPPoE, frame, modifiers));
			}
			// IP next?
			if(ethertype == ETH_P_IP){
				return(decap(data + l2_header_length, length - l2_header_length, IPv4, frame, modifiers));
			}
			// IPv6 next?
			if(ethertype == ETH_P_IPV6){
				return(decap(data + l2_header_length, length - l2_header_length, IPv6, frame, modifiers));
			}
			// Something else next?
			return(decap(data + l2_header_length, length - l2_header_length, UNKNOWN, frame, modifiers));
			break;
		case VLAN:
			if(length < 4) return(frame);
			frame->plen = length - 4;
			frame->payload = data + 4;
			memcpy(frame->etype, data+2, 2);
			ethertype = ntohs(*(uint16_t *)(data+2));

			// Just skim over VLANs and determine the next encap type from the EtherType
			// VLAN tag next?
			if(ethertype == ETH_P_8021Q || ethertype == ETH_P_QINQ1){
				return(decap(data + 4, length - 4, VLAN, frame, modifiers));
			}
			// MPLS tag next?
			if(ethertype == ETH_P_MPLS_UC){
				return(decap(data + 4, length - 4, MPLS, frame, modifiers));
			}
			// PPPoE session data next?
			if(ethertype == ETH_P_PPP_SES){
				return(decap(data + 4, length - 4, PPPoE, frame, modifiers));
			}
			// IP next?
			if(ethertype == ETH_P_IP){
				return(decap(data + 4, length - 4, IPv4, frame, modifiers));
			}
			// IPv6 next?
			if(ethertype == ETH_P_IPV6){
				return(decap(data + 4, length - 4, IPv6, frame, modifiers));
			}
			// Something else next?
			return(decap(data + 4, length - 4, UNKNOWN, frame, modifiers));
			break;
		case MPLS:
			if(length < 4) return(frame);
			frame->plen = length - 4;
			frame->payload = data + 4;

			// Check bottom of stack bit to decide whether to keep stripping MPLS or try for Ethernet
			if((data[2] & '\x01') == 0){
				return(decap(data + 4, length - 4, MPLS, frame, modifiers));	// Not BOS, more MPLS
			}

			if((data[4] & '\xf0') == '\x40'){						// IPv4 (guess)
				memcpy(frame->etype, "\x08\x00", 2);
				return(decap(data + 4, length - 4, IPv4, frame, modifiers));
			} else if((data[4] & '\xf0') == '\x60'){				// IPv6 (guess)
				memcpy(frame->etype, "\x86\xdd", 2);
				return(decap(data + 4, length - 4, UNKNOWN, frame, modifiers));
			} else {
				if(memcmp(data + 4, "\x00\x00\x00\x00", 4) == 0){
					// guessing ethernet control word present...
					return(decap(data + 8, length - 8, ETHERNET, frame, modifiers));
				} else {
					return(decap(data + 4, length - 4, ETHERNET, frame, modifiers));	// Ethernet (guess)
				}
			}
		break;
		case PPPoE:
			// Only a PPP header can follow a PPPoE session header
			if(length < 6) return(frame);
			frame->payload = data;
			frame->plen = length;
			return(decap(data + 6, length - 6, PPP, frame, modifiers));
		break;
		case PPP:
			// Should be IPv4 or IPv6 behind this, otherwise bail.
			if(length < 2) return(frame);

			if(memcmp(data, "\x00\x21", 2) == 0){				// IPv4
				memcpy(frame->etype, "\x08\x00", 2);
				frame->plen = length - 2;
				frame->payload = data + 2;
				return(decap(data + 2, length - 2, IPv4, frame, modifiers));
			} else if(memcmp(data, "\x00\x57", 2) == 0){		// IPv6
				memcpy(frame->etype, "\x86\xdd", 2);
				frame->plen = length - 2;
				frame->payload = data + 2;
				return(decap(data + 2, length - 2, UNKNOWN, frame, modifiers));
			}
			else return(frame);
		break;
		case IPv4:
		case IPv6:
			if(type == IPv4) {
				min_length = 20;
			} else if(type == IPv6) {
				min_length = 40;
			}
			// If the protocol is IP we may find some GRE / L2TP encap
			if(length < min_length) return(frame);
			if(type == IPv4) {
				header_length = 4 * (data[0] & 15);
			} else if(type == IPv6) {
				header_length = 40;
			}
			if(length < header_length) return(frame);

			frame->payload = data;
			frame->plen = length;

			// If the frame is a fragment and we're re-assembling, don't decapsulate any further at this point
			if(type == IPv4 && (((data[6] & '\x3f') | data[7]) != 0) && ((modifiers & NODEFRAG) == 0)) {
				frame->fragment = 1;
				return(frame);
			}

			int l4_proto = -1;
			if(type == IPv4) {
				l4_proto = data[9];
			} else if(type == IPv6) {
				l4_proto = data[6];
			}

			// If not a fragment or we're skipping re-assembly, try for more encap
			if(l4_proto == '\x11'){			// UDP
				return(decap(data + header_length, length - header_length, UDP, frame, modifiers));
			} else if(l4_proto == '\x2f'){	// GRE
				return(decap(data + header_length, length - header_length, GRE, frame, modifiers));
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
				int ethertype = ntohs(*(uint16_t *)(data+2));

				// VLAN tag next?
				if(ethertype == ETH_P_8021Q || ethertype == ETH_P_QINQ1){
					return(decap(frame->payload, frame->plen, VLAN, frame, modifiers));
				}
				// MPLS tag next?
				if(ethertype == ETH_P_MPLS_UC){
					return(decap(frame->payload, frame->plen, MPLS, frame, modifiers));
				}
				// PPPoE session data next?
				if(ethertype == ETH_P_PPP_SES){
					return(decap(frame->payload, frame->plen, PPPoE, frame, modifiers));
				}
				// IP next?
				if(ethertype == ETH_P_IP){
					return(decap(frame->payload, frame->plen, IPv4, frame, modifiers));
				}
				// IPv6 next?
				if(ethertype == ETH_P_IPV6){
					return(decap(frame->payload, frame->plen, IPv6, frame, modifiers));
				}
				// Something else next?
				return(frame);
			}
		break;
		case UDP:
			// If the protocol is UDP, check for L2TP port numbers
			if(length < 8) return(frame);
			dst_port = ntohs(*(uint16_t *)(data + 2));
			if(dst_port == 1701){		// L2TP
				return(decap(data + 8, length - 8, L2TP, frame, modifiers));
			} else if(dst_port == 2152){		// GTP
				return(decap(data + 8, length - 8, GTP, frame, modifiers));
			} else if(dst_port == 4789 || dst_port == 8472){		// VXLAN
				return(decap(data + 8, length - 8, VXLAN, frame, modifiers));
			} else return(frame);
		break;
		case L2TP:
			// If we get an L2TPv2 data packet, deal with the payload.
			// This only handles zero offset with no Ns / Nr as produced by IOS. Will need
			// to test this against JunOS at some point to see if behaviour is different.
			if(length < 10) return(frame);
			if(	(data[0] == '\x02') &&
				(data[1] == '\x02') &&
				(data[6] == '\x00') &&
				(data[7] == '\x00') &&
				(data[8] == '\xff') &&
				(data[9] == '\x03') )
					return(decap(data + 10, length - 10, PPP, frame, modifiers));
			// Otherwise, not L2TPv2 frame in the basic format we can handle
			return(frame);
		break;
		case GTP:
			// If we get a GTP data packet, deal with the payload.
			if(length < 28) return(frame);

			// If frame is not a GTP U frame then don't bother decap-ing it
			if(((data[0] & '\xe0') != '\x20') || (data[1] != '\xff')) return(frame);

			vlen = (256*(unsigned char)data[2])+(unsigned char)data[3];

			if((data[0] & '\x07') != 0) {						// Long header
				if(vlen > (length - 8)) return(frame);			// If the header says length > remaining data, bail out

				pos = 12;
				if(((unsigned char)data[0] & '\x04') != 0) {
					while((unsigned char)data[pos-1] != 0){		// Shave off any extension headers
						if(((unsigned char)data[pos]) == '\x00') return(frame);	// avoid getting stuck for zero length extension headers
						pos += (((unsigned char)data[pos]) * 4);
						if(pos > vlen) return(frame);			// Check we're not over-reading
					}
				}
			} else {											// Short header
				pos = 8;
			}

			// Parsed OK, update frame template and parse IPv4
			frame->plen = length - pos;
			frame->payload = data + pos;
			memcpy(frame->etype, "\x08\x00", 2);
			return(decap(data + pos, length - pos, IPv4, frame, modifiers));

		break;
		case VXLAN:
			// If we get a VXLAN candidate packet, sanity check then deal with the payload.
			if(length < 22) return(frame); // Too short

			// Assume all reserved bits are zero - may need to update this in future
			if(memcmp(data, "\x08\x00\x00\x00", 4) != 0){
				// header not found, bail out
				return(frame);
			} else {
				// VXLAN header present, update frame and go for Ethernet
				return(decap(data + 8, length - 8, ETHERNET, frame, modifiers));
			}

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

int parse_pcap(FILE *capfile, FILE *outfile, fragment_list_t **fragtree, int modifiers){
	char 				*memblock = NULL;
	frame_t				*frame = NULL,
						*decapped = NULL;
	guint32				caplen = 0;
	int					decapcount = 0,
						fragmented = 0;
	pcaprec_hdr_t		*rechdr = NULL;

	if(fragtree == NULL){
		printf("\nDecapsulating...\n");
	} else {
		printf("\nReassembling...\n");
	}

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
	if(((pcap_hdr_t*)memblock)->magic_number != 0xa1b2c3d4){
		printf("\nError!\nThis is not a valid pcap file. If it has been saved as pcap-ng\nconsider converting it to original pcap format with tshark or similar.\n");
		if(memblock != NULL) free(memblock);
		return(0);
	}
	// Create the frame template used in the decap process
	frame = malloc(sizeof(frame_t));
	if(frame == NULL){
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

	// Get the link type.
	char linktype = ETHERNET;
	if (((pcap_hdr_t*)memblock)->network == DLT_LINUX_SLL) {
		linktype = SLL;
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
		frame->l2 = NULL;
		memcpy(frame->etype, "\x00\x00", 2);
		frame->payload = NULL;
		frame->plen = 0;
		frame->fragment = 0;

		if((modifiers & DEBUGGING) == DEBUGGING){
			printf("handling frame %u of %u bytes.\n", decapcount+1, caplen);
			if(caplen > 13) hexdump(memblock, 14);
			printf("\n\n");
		}

		// If we are handed a NULL pointer, decapsulate. Otherwise, defragment.
		if(fragtree == NULL){
			decapped = decap(memblock, caplen, linktype, frame, modifiers);
			fragmented = (fragmented | decapped->fragment);
		} else {
			decapped = reassemble(memblock, caplen, linktype, frame, fragtree);
		}

		// Write the decapsulated frame to the output file
		if(decapped != NULL){
			decapcount++;

			int ethertype_offset = -1;
			int l2_header_length = -1;
			if(linktype == ETHERNET) {
				ethertype_offset = 12;
				l2_header_length = 14;
			} else if(linktype == SLL) {
				ethertype_offset = 14;
				l2_header_length = 16;
			}
			rechdr->incl_len = decapped->plen+l2_header_length;
			rechdr->orig_len -= caplen - rechdr->incl_len;

			if(fwrite(rechdr, 1, sizeof(pcaprec_hdr_t), outfile) != sizeof(pcaprec_hdr_t)){
				printf("Error: unable to write pcap record header to output file!\n");
				return(0);
			}
			if(fwrite(decapped->l2, 1, ethertype_offset, outfile) != ethertype_offset){
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
		}
	}
	if(rechdr != NULL){
		free(rechdr);
	}

	if(fragmented == 1){
		return(-1);
	} else {
		return(decapcount);
	}
}

int main(int argc, char *argv[]){
// The main function basically just calls other functions to do the work.
	params_t			*parameters = NULL;
	FILE				*infile = NULL,
						*outfile = NULL,
						*tempfile = NULL;
	int					packets = 0;
	fragment_list_t		*fraglist = NULL,
						*cur = NULL;

	// Parse our command line parameters and verify they are usable. If not, show help.
	parameters = parseParams(argc, argv);
	if(parameters == NULL){
		printf("stripe: a utility to remove VLAN tags, MPLS shims, PPPoE, L2TP headers,\n");
		printf("etc. from the frames in a PCAP file and return untagged IP over Ethernet.\n");
		printf("Version %s, %s\n\n", SWVERSION, SWRELEASEDATE);
		printf("Usage:\n");
		printf("%s -r inputcapfile -w outputcapfile [-f] [-v]\n\n",argv[0]);
		printf("Where:\ninputcapfile is a tcpdump-style .cap file containing encapsulated IP \n");
		printf("outputcapfile is the file where the decapsulated IP will be saved\n");
		printf("-f instructs stripe not to attempt to merge fragmented IP packets\n");
		printf("-v enables verbose debugging\n");
		return(1);
	}

	// Attempt to open the capture file, defragment and decap:
	infile = fopen(parameters->infile,"rb");
	if (infile == NULL) {
		printf("\nError!\nUnable to open input capture file!\n");
		return(1);
	}
	tempfile = tmpfile();
	if(tempfile == NULL){
		printf("Error - could not create temporary file!\n");
		return(1);
	}
	outfile = fopen(parameters->outfile, "wb");
	if(outfile == NULL){
		printf("Error - could not open output file!\n");
		return(1);
	}

	if((parameters->modifiers & NODEFRAG) == 0){
		packets = parse_pcap(infile, tempfile, &fraglist, parameters->modifiers);
		rewind(tempfile);
		packets = parse_pcap(tempfile, outfile, NULL, parameters->modifiers);
	} else {
		printf("Reassembly disabled...\n");
		packets = parse_pcap(infile, outfile, NULL, parameters->modifiers);
	}

	fclose(infile);
	fclose(tempfile);
	fclose(outfile);



	// If we need to re-assemble, do so and re-parse
	while((packets == -1) && ((parameters->modifiers & NODEFRAG) == 0)){
		printf("got fragments, need to reassemble...\n");
		// Create temporary file for use when re-assembling fragments
		tempfile = tmpfile();
		if(tempfile == NULL){
			printf("Error - could not create temporary file!\n");
			return(1);
		}
		// Re-open outfile for reading
		outfile = fopen(parameters->outfile, "rb");
		if(outfile == NULL){
			printf("Error - could not open output file!\n");
			return(1);
		}

		// Re-assemble into the temporary file
		parse_pcap(outfile, tempfile, &fraglist, parameters->modifiers);
		fclose(outfile);

		// Warn if some frames had missing fragments
		if(fraglist != NULL){
			printf("Warning: missing fragment(s) on reassembly.\n");
			// Free up that junk, we're never going to use it!
			while(fraglist != NULL){
				cur= fraglist->next;
				free(fraglist->ipinfo);
				free(fraglist->data);
				free(fraglist->holes);
				if(fraglist->header != NULL) free(fraglist->header);
				free(fraglist);
				fraglist = cur;
			}

		}

		outfile = fopen(parameters->outfile, "wb");
		if(outfile == NULL){
			printf("Error - could not open output file!\n");
			return(1);
		}
		// Decap the re-assembled packets
		rewind(tempfile);
		packets = parse_pcap(tempfile, outfile, NULL, parameters->modifiers);
		fclose(tempfile);
	}

	printf("\n%d frames processed.\n", packets);



	return(0);
}
