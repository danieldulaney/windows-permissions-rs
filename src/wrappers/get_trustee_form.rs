use crate::constants::TrusteeForm;
use crate::Trustee;

/// Wraps GetTrusteeFormW
///
/// Returns `Err` on invalid form with the raw content of the field
#[allow(non_snake_case)]
pub fn GetTrusteeForm<'s>(trustee: &Trustee<'s>) -> Result<TrusteeForm, u32> {
    let form = unsafe { winapi::um::aclapi::GetTrusteeFormW(trustee.as_ptr() as *mut _) };

    TrusteeForm::from_raw(form).ok_or_else(|| form)
}
