#pragma once

// Phase 0 smoke test for the DAVE/MLS port (see Gestione plan: kind-moseying-kettle).
// Proves that library/mlspp_buildtest can compile with -fexceptions -frtti via a
// target-specific Makefile override while the rest of TriCord keeps -fno-exceptions
// -fno-rtti. Returns true if an internal throw/catch round-trip succeeded.
bool daveExceptionSmokeTest();
