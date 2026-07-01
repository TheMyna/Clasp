// GPL-3.0-or-later. pybind11 bindings for the CLASP CL backend.
#include <pybind11/pybind11.h>
#include "cl_ops.cpp"
namespace py = pybind11;

PYBIND11_MODULE(clbicycl, m) {
    m.doc() = "CLASP CL backend over BICYCL (stage one: CL ops + single-key dec)";
    py::class_<CL_HSMqk::CipherText, std::shared_ptr<CL_HSMqk::CipherText>>(m, "CipherText");
    py::class_<ClContext>(m, "ClContext")
        .def(py::init<int>(), py::arg("sec_bits") = 128)
        .def("enc",  &ClContext::enc)
        .def("add",  &ClContext::add)
        .def("scal", &ClContext::scal)
        .def("dec",  &ClContext::dec)
        .def("cleartext_bound", &ClContext::cleartext_bound)
        .def("add_norand", &ClContext::add_norand);
}
