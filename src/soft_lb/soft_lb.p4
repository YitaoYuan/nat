//[180, 164, 148, 132]

/* -*- P4_16 -*- */
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


struct headers {

}

struct nf_port_t{
    bit<2>  port_type; 
    bit<14> unused;
}

struct ingress_metadata {
    nf_port_t nf_port_hdr;
}

struct egress_metadata {

}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser IngressParser(packet_in packet,
               out headers hdr,
               out ingress_metadata meta,
               out ingress_intrinsic_metadata_t ig_intr_md) {


    state start {
        packet.extract(ig_intr_md);

        transition select(ig_intr_md.resubmit_flag) {
            0 : parse_port_metadata;
        }
    }

    state parse_port_metadata {
        meta.nf_port_hdr = port_metadata_unpack<nf_port_t>(packet);
        transition accept;
    }
}

control Ingress(
        inout headers hdr,
        inout ingress_metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    action set_egress_port(bit<9> port) {
        ig_intr_dprs_md.drop_ctl = 0;
        ig_intr_tm_md.ucast_egress_port = port;
    }

    apply {
        ig_intr_tm_md.bypass_egress = 1;
        if(ig_intr_md.ingress_port == 180) // 1->4
            set_egress_port(132);
        else if(ig_intr_md.ingress_port == 132) // 4->3
            set_egress_port(148);
        else if(ig_intr_md.ingress_port == 148) // 3->1
            set_egress_port(180);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control IngressDeparser(
        packet_out packet,
        inout headers hdr,
        in ingress_metadata meta,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    apply{
    }
}

parser EgressParser(packet_in packet,
               out headers hdr,
               out egress_metadata meta,
               out egress_intrinsic_metadata_t eg_intr_md) {
    state start{
        packet.extract(eg_intr_md);
        transition accept;
    }
}

control Egress(
        inout headers hdr,
        inout egress_metadata meta,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_prsr_md,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

    apply { }
}

control EgressDeparser(packet_out packet,
                  inout headers hdr,
                  in egress_metadata meta,
                  in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {
            
    apply { }
}

Pipeline(IngressParser(), Ingress(), IngressDeparser(), EgressParser(), Egress(), EgressDeparser()) pipe;

Switch(pipe) main;
