set(PYBIND_WRAPPER_SOURCE_DIR "${PROJECT_SOURCE_DIR}/src/python_bindings")
set(PYBIND_PATH "${PROJECT_SOURCE_DIR}/ext_py_binding_lib")
set(AES_LIB_INC_DIR "${PROJECT_SOURCE_DIR}/inc")

# pybind11
add_subdirectory(${PYBIND_PATH}/pybind11)

pybind11_add_module (
    py_sc_aes 
    ${PYBIND_WRAPPER_SOURCE_DIR}/py_bindings.cpp
)

target_link_libraries(py_sc_aes PUBLIC aes_lib)

target_include_directories (
    py_sc_aes 
    PRIVATE ${AES_LIB_INC_DIR}
)
