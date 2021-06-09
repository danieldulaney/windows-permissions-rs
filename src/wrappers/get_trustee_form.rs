use crate::constants::TrusteeForm;
use crate::Trustee;

/// Wraps [`GetTrusteeFormW`](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-gettrusteeformw)
///
/// If the form value is not recognized, returns `Err` with the raw value.
#[allow(non_snake_case)]
pub fn GetTrusteeForm<'s>(trustee: &Trustee<'s>) -> Result<TrusteeForm, u32> {
    let form = unsafe { winapi::um::aclapi::GetTrusteeFormW(trustee.as_ptr() as *mut _) };

    TrusteeForm::from_raw(form).ok_or_else(|| form)
}
