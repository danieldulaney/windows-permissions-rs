use crate::constants::TrusteeForm;
use crate::Trustee;

/// Wraps [`GetTrusteeFormW`](https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-gettrusteeformw)
///
/// If the form value is not recognized, returns `Err` with the raw value.
#[allow(non_snake_case)]
pub fn GetTrusteeForm(trustee: &Trustee) -> Result<TrusteeForm, i32> {
    let form = unsafe {
        windows_sys::Win32::Security::Authorization::GetTrusteeFormW(trustee.as_ptr() as *mut _)
    };

    TrusteeForm::from_raw(form).ok_or(form)
}
