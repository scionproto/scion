@0xe6c88f91b6a1209e;
using Go = import "go.capnp";
$Go.package("proto");
$Go.import("github.com/scionproto/scion/go/proto");

struct RoutingPolicyExt{
    set @0 :Bool;   # Is the extension present? Every extension must include this field.
    polType @1 :UInt8;  # The policy type
    ifID @2 :UInt64;
    isdases @3 :List(UInt64);
}

struct ISDAnnouncementExt{
    set @0 :Bool;   # TODO(Sezer): Implement announcement extension
}

struct HiddenPathSegExtn{
    set @0 :Bool;
}

struct StaticInfoExtn {
   ei @0 :Latencyinfo;
   gi @1 :Geoinfo;
   lt @2 :Linktypeinfo;
   bw @3 :Bandwidthinfo;
   ih @4 :Internalhopsinfo;
   ni @5 :Note;

   struct Latencyinfo {
      lnpcs @0 :List(Lnpcluster);
      lpcs @1 :List(Lpcluster);
      egresslatency @2 :UInt16;
      intooutlatency @3 :UInt16;

      struct Lnpcluster {
         clusterdelay @0 :UInt16;
         interfaces @1 :List(UInt64);
      }

      struct Lpcluster {
         clusterdelay @0 :UInt16;
         lpps @1 :List(Lppair);

         struct Lppair {
            interface @0 :UInt64;
            interdelay @1 :UInt16;
         }
      }
   }

   struct Bandwidthinfo {
      bwcs @0 :List(Bwcluster);
      egressBW @1 :UInt32;
      intooutBW @2 :UInt32;

      struct Bwcluster {
         clusterbw @0 :UInt32;
         interfaces @1 :List(UInt64);
      }
   }

   struct Geoinfo {
      gcs @0 :List(Geocluster);

      struct Geocluster {
         cl @0 :Clusterlocation;
         interfaces @1 :List(UInt64);

         struct Clusterlocation {
            latitude @0 :Float32;
            longitude @1 :Float32;
            civadd @2 :Data;
         }
      }
   }

   struct Linktypeinfo {
      ltnpcs @0 :List(Ltnpcluster);
      ltpcs @1 :List(Ltpcluster);
      egresslt @2 :Linktype;
      intooutlt @3 :Linktype;

      enum Linktype{
         direct @0;
         multihop @1;
         opennet @2;
         undisclosed @3;
      }

      struct Ltnpcluster {
         clusterlt @0 :Linktype;
         interfaces @1 :List(UInt64);
      }

      struct Ltpcluster {
         clusterlt @0 :Linktype;
         ltpps @1 :List(Ltppair);

         struct Ltppair {
            interface @0 :UInt64;
            interlt @1 :Linktype;
         }
      }
   }

   struct Internalhopsinfo {
      hcs @0 :List(Hopcluster);
      intouthops @1 :UInt8;

      struct Hopcluster {
         clusterhops @0 :UInt8;
         interfaces @1 :List(UInt64);
      }
   }

   struct Note {
      defaultnote @0 :Data;
      specificnote @1 :Data;
   }
}
