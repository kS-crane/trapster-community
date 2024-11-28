import struct

# details of dns packet : https://courses.cs.duke.edu/fall16/compsci356/DNS/DNS-primer.pdf
# code from https://stackoverflow.com/questions/16977588/reading-dns-packets-in-python

def decode_labels(message, offset):
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF), offset

        if (length & 0xC0) != 0x00:
            raise "unknown label encoding"

        offset += 1

        if length == 0:
            return labels, offset

        labels.append(*struct.unpack_from("!%ds" % length, message, offset))
        try:
            labels[-1] = labels[-1].decode()
        except UnicodeDecodeError:
            labels[-1] = str(labels[-1])

        offset += length


DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")

DNS_ANSWER_SECTION_FORMAT = struct.Struct("!6H")

def decode_question_section(message, offset, qdcount):
    questions = []

    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)

        qtype, qclass = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
        offset += DNS_QUERY_SECTION_FORMAT.size

        question = {"domain_name": qname,
                    "query_type": qtype,
                    "query_class": qclass}

        questions.append(question)

    return questions, offset

def decode_answer_section(message, offset, ancount):
    answers = []

    for _ in range(ancount):
        aname, offset = decode_labels(message, offset)

        # Decode the answer section (skipping the name pointer: 2 bytes for `c0`)
        query_type, query_class, ttl, rdlength = struct.unpack("!HHIH", message[offset:offset + 10])
        offset += 10 

        #get ip based on rdata len
        rdata = message[offset:offset + rdlength]
        ip_address = ".".join(map(str, rdata))

        # Assign variables
        answer = {
            "domain_name": aname,
            "query_type": query_type,
            "query_class": query_class,
            "ttl": ttl,
            "ip_address": ip_address
        }

        answers.append(answer)

    return answers, offset


DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")

def decode_dns_message(message):

    id, flags, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(message)
    
    qr = (flags & 0x8000) != 0 
    opcode = (flags & 0x7800) >> 11 
    aa = (flags & 0x0400) != 0 
    tc = (flags & 0x200) != 0 
    rd = (flags & 0x100) != 0 
    ra = (flags & 0x80) != 0
    z = (flags & 0x70) >> 4
    rcode = flags & 0xF

    offset = DNS_QUERY_MESSAGE_HEADER.size
    questions, offset = decode_question_section(message, offset, qdcount)
    answers, offset = decode_answer_section(message, offset, ancount)


    result = {"id": id,
              "is_response": qr,
              "opcode": opcode,
              "is_authoritative": aa,
              "is_truncated": tc,
              "recursion_desired": rd,
              "recursion_available": ra,
              "reserved": z,
              "response_code": rcode,
              "question_count": qdcount,
              "answer_count": ancount,
              "authority_count": nscount,
              "additional_count": arcount,
              "questions": questions,
              
              }
    if answers != []:
        result["answers"] =  answers

    return result