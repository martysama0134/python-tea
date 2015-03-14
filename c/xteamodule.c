// Copyright (c) 2013, martysama0134
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
// Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
// Neither the name of martysama0134 nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#define MODULE_VERSION "1.12.20130730"

#include <Python.h>
#include <stdint.h>	//uint32_t, uint_fast32_t

#if !defined(PY_VERSION_HEX) || (PY_VERSION_HEX < 0x010502f0)
# error "Need Python version 1.5.2 or greater"
#endif

#undef UNUSED
#define UNUSED(var)	((void)&var)

static PyObject* XteaError;

#define XTDELTA		0x9e3779b9u
#define XTROUND		32u
#define XTSUM		0xc6ef3720u

void XTeaEncrypt(uint32_t* w, const uint32_t* v, const uint32_t* k)
{
	register uint32_t y = v[0];
	register uint32_t z = v[1];
	register uint32_t sum = 0;

	uint_fast32_t i = 0;
	while (i++ < XTROUND) {
		y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + (k[sum & 3]));
		sum += XTDELTA;
		z += (((y << 4) ^ (y >> 5)) + y) ^ (sum + (k[(sum >> 11) & 3]));
	}
	w[0] = y;
	w[1] = z;
}

void XTeaDecrypt(uint32_t* w, const uint32_t* v, const uint32_t* k)
{
	register uint32_t y = v[0];
	register uint32_t z = v[1];
	register uint32_t sum = XTSUM; //XTDELTA * XTROUND;

	uint_fast32_t i = 0;
	while (i++ < XTROUND) {
		z -= (((y << 4) ^ (y >> 5)) + y) ^ (sum + (k[(sum >> 11) & 3]));
		sum -= XTDELTA;
		y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + (k[sum & 3]));
	}
	w[0] = y;
	w[1] = z;
}

void XTeaEncryptStr(uint32_t* w, const uint32_t* v, const uint32_t* k, uint32_t size)
{
	uint_fast32_t rounds = 0;
	do {
		XTeaEncrypt(w, v, k);
		v += 2;
		w += 2;
		++rounds;
	} while ( size/8 > rounds );
}

void XTeaDecryptStr(uint32_t* w, const uint32_t* v, const uint32_t* k, uint32_t size)
{
	uint_fast32_t rounds = 0;
	do {
		XTeaDecrypt(w, v, k);
		v += 2;
		w += 2;
		++rounds;
	} while ( size/8 > rounds );
}




// ************************************
// ENCRYPT
// ************************************
static /* const */ char encrypt_all__doc__[] = "encrypt_all(string, key)\n";

static PyObject* encrypt_all(PyObject* dummy, PyObject* args)
{
	PyObject* result_str;
	const char *v, *k;
	uint32_t v_len, k_len;
	char* xteabuf;

	/* init */
	UNUSED(dummy);
	if (!PyArg_ParseTuple(args, "s#s#", &v, &v_len, &k, &k_len))
		return NULL;
	if ((v_len & 7) || (!v_len))
		return NULL;
	if (k_len != 16)
		return NULL;
	
	result_str = PyString_FromStringAndSize(NULL, v_len);
	if (result_str == NULL)
		return PyErr_NoMemory();

	xteabuf = PyString_AsString(result_str);

	XTeaEncryptStr((uint32_t*)xteabuf, (const uint32_t*)v, (const uint32_t*)k, v_len);

	return result_str;
}

// ************************************
// DECRYPT
// ************************************
static /* const */ char decrypt_all__doc__[] = "decrypt_all(string, key)\n";

static PyObject* decrypt_all(PyObject* dummy, PyObject* args)
{
	PyObject *result_str;
	const char *v, *k;
	uint32_t v_len, k_len;
	char* xteabuf;
	
	/* init */
	UNUSED(dummy);
	if (!PyArg_ParseTuple(args, "s#s#", &v, &v_len, &k, &k_len))
		return NULL;
	if ((v_len & 7) || (!v_len))
		return NULL;
	if (k_len != 16)
		return NULL;
	
	result_str = PyString_FromStringAndSize(NULL, v_len);
	if (result_str == NULL)
		return PyErr_NoMemory();

	xteabuf = PyString_AsString(result_str);
	
	XTeaDecryptStr((uint32_t*)xteabuf, (const uint32_t*)v, (const uint32_t*)k, v_len);

	return result_str;
}

static /* const */ PyMethodDef methods[] =
{
	{"encrypt_all", (PyCFunction)encrypt_all, METH_VARARGS, encrypt_all__doc__},
	{"decrypt_all", (PyCFunction)decrypt_all, METH_VARARGS, decrypt_all__doc__},
	{NULL, NULL, 0, NULL}
};

static /* const */ char module_documentation[]=
"XTEA Block Cipher Module\n\n"
"encrypt_all(string, key)\n"
"decrypt_all(string, key)\n"
;

#ifdef _MSC_VER
_declspec(dllexport)
#endif
void init_xtea(void)
{
	PyObject *m, *d, *v;

	m = Py_InitModule4("_xtea", methods, module_documentation, NULL, PYTHON_API_VERSION);
	d = PyModule_GetDict(m);

	XteaError = PyErr_NewException("_xtea.error", NULL, NULL);
	PyDict_SetItemString(d, "error", XteaError);

	v = PyString_FromString("martysama0134");
	PyDict_SetItemString(d, "__author__", v);
	Py_DECREF(v);
	v = PyString_FromString(MODULE_VERSION);
	PyDict_SetItemString(d, "__version__", v);
	Py_DECREF(v);
}







