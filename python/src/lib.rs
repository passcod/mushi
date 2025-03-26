use pyo3::prelude::*;

#[pymodule(name = "mushi")]
pub mod export {
    use pyo3::prelude::*;

    #[pyclass]
    pub struct EndpointKey(mushi::EndpointKey);

    #[pymethods]
    impl EndpointKey {
        #[new]
        fn new(pem: String) -> PyResult<Self> {
            todo!()
        }
    }
}
