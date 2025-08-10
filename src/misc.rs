//!
//! This file contains miscellaneous function definitions that may be
//! helpful.
//!
//! Some examples are inline functions or macros defined in WDK headers
//! that don't get bindings because they are inline.
//!
#![allow(non_snake_case)]

use wdk_sys::{
    BOOLEAN, PIO_COMPLETION_ROUTINE, PIO_STACK_LOCATION, PIRP, PVOID, SL_INVOKE_ON_CANCEL,
    SL_INVOKE_ON_ERROR, SL_INVOKE_ON_SUCCESS,
};

pub unsafe fn IoSetCompletionRoutine(
    Irp: PIRP,
    CompletionRoutine: PIO_COMPLETION_ROUTINE,
    Context: PVOID,
    InvokeOnSuccess: BOOLEAN,
    InvokeOnError: BOOLEAN,
    InvokeOnCancel: BOOLEAN,
) {
    debug_assert!(
        if InvokeOnSuccess > 0 || InvokeOnError > 0 || InvokeOnCancel > 0 {
            CompletionRoutine.is_some()
        } else {
            true
        }
    );

    let irpSp = IoGetNextIrpStackLocation(Irp);
    (*irpSp).CompletionRoutine = CompletionRoutine;
    (*irpSp).Context = Context;
    (*irpSp).Control = 0;

    if InvokeOnSuccess > 0 {
        (*irpSp).Control = SL_INVOKE_ON_SUCCESS as u8;
    }

    if InvokeOnError > 0 {
        (*irpSp).Control |= SL_INVOKE_ON_ERROR as u8;
    }

    if InvokeOnCancel > 0 {
        (*irpSp).Control |= SL_INVOKE_ON_CANCEL as u8;
    }
}

pub unsafe fn IoGetNextIrpStackLocation(Irp: PIRP) -> PIO_STACK_LOCATION {
    debug_assert!((*Irp).CurrentLocation > 0);

    return (*Irp)
        .Tail
        .Overlay
        .__bindgen_anon_2
        .__bindgen_anon_1
        .CurrentStackLocation
        .sub(1);
}
