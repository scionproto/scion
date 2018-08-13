# Path Service Design (Go)

## Request Handlers

The path service needs to handle multiple requests. We use the messenger to register request handlers. The following requests need to be handled:

* __TRCRequest:__ Use handler of existing truststore.
* __ChainRequest:__ Use handler of existing truststore.
* __Path registration:__ A handler for the existing Path Registration request should be implemented.
* __Path requests:__ A handler for the existing SegReq should be implemented.
* __Path Revocation:__ A handler for the existing Path revocation message should be implemented.
* __Path synchronization:__ Currently the python path server uses a push model. A PS that receives a down segment propagates this to the other PSes in the ISD-core. To support a smooth migration path we should also implement this in the go PS. Note that we should add a flag to disable this (for CI builds and for a future go-only env)
* __Path changes since:__ Used for the new replication of down segments. The service should return all the ids of changed segments since a certain point in time. The requesting PS can then request the affected segments. The python server will not support this mechanism but we will receive the old path sync message from it, so this is not a big problem.

## Replication of down segments

In the ISD-core the ASes must have the same set of down segments. A core PS in an AS should periodically request path changes (since last query) at the PSes in all other core ASes. Once the PS knows what changed, it should fetch the locally missing down segments.

## Path lookup

### Logic flow

Local means in the same ISD as the current PS, remote means in a different ISD.

#### Common logic

* Receive path request R of type SegReq
* For non-core PS: Check source (R.RawSrcIA): must either be unset, or set to the local IA otherwise return an error/empty reply
* Check destination (R.RawDstIA):
  * If the R.RawDstIA is not set or invalid (i.e., ISD is 0) or represents the local IA, immediately return an error/empty reply
* Define `GetCached(Seg, cPS)` := if last lookup Seg.Dst is longer than a configured time ago, request at cPS and save result in cache, then return cached version. If we currently do not have a path to cPS we should hold the request until either we have a path or the request timed out.
* Request Paths: Note that results should always be filtered, any segments with revoked on-path interface should be dropped. See steps below.

#### Non-core PS

* If Dst == Core-AS:
  * For each local core-AS x, for which an up segment exists && isNot(dst):
    * GetCached(coreSeg{dst->x}, x)
  * Return up-segments, which have a connecting core segment or which end in dst, and the core segments (5.1.1.1.1).
* Else // Dst == Non-Core-AS:
  * GetCached(downSeg{*->dst}, any local cPS)
  * Filter down segments, remove revoked ones.
  * For each core AS x, that is at the start of a down segment:
    * For each local core AS y, for which an up segment exists && x != y: GetCached(coreSeg{x->y}, y)
  * Filter down segments, only keep reachable ones
  * Return the down, core, and up segments.

#### Core PS

* If destination is local:
  * If Dest is ISD-0: return empty
  * Else if Dest is core AS: return coreSeg{dst->self}
  * Else
    * If request from different AS: return downSeg{*->dst} (from DB)
    * Else return downSeg{*->dst} (from DB) and for each core AS x, that is at the start of a down segment return the coreSegs{x->self}
* If destination is remote:
  * If Dest is ISD-0 return any coreSeg{ISD-*->self}
  * Else if Dest is core AS: return coreSeg{dst->self}
  * Else
    * If request from different AS: return GetCached(downSeg{*->dst}, any cPS in DestISD)
    * Else return GetCached(downSeg{*->dst}, any cPS in DestISD) and for each core AS x, that is at the start of a down segment return the coreSegs{x->self}

## Revocations

Revocations can come from inside the ISD in form of a CtrlPld.PathMgmt.SRevInfo from the border router, beacon service, or from the PS, or from anywhere in the form of an SCMP revocation, or if a core PS requests down segments of a core PS in another ISD the response should contain the relevant revocations.

Note that, differing from the book, a revocation should no longer result in the deletion of a path segment. Instead we only filter when using path segments.

### Logic flow

* Receive revocation R
* If R is a CtrlPld.PathMgmt.SRevInfo && source is not in same ISD
  * Ignore R // SRevInfo should only come from within the same ISD.
* Verify R, if invalid drop it and return.
* Save R in the revocation cache
* Forward revocation in non-core PS:
  * If revoked interface belongs to this AS OR revocation is from a different ISD:
    * Inform all core PSes in the local ISD
* Forward revocation in core PS:
  * If revoked interface belongs to this AS OR
      Revocation is from a BR and it originated from a different ISD
    * Inform all other core ASes.
  * Note that if a cPS queries a cPS of another ISD for down segments it should also get the relevant revocations for the segments. These revocations do not need to be forwarded to other cPSes.
