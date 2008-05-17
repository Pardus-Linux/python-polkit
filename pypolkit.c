/*
* Copyright (c) 2008, TUBITAK/UEKAE
* Copyright (c) 2008, Harald Hoyer
*
* Permission is hereby granted, free of charge, to any person
* obtaining a copy of this software and associated documentation
* files (the \"Software\"), to deal in the Software without
* restriction, including without limitation the rights to use, copy,
* modify, merge, publish, distribute, sublicense, and/or sell copies
* of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be
* included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND,
* EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
* NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
* HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
* DEALINGS IN THE SOFTWARE.
*
*/

#include <polkit-grant/polkit-grant.h>
#include <polkit-dbus/polkit-dbus.h>
#include <Python.h>
#include <datetime.h>
#include <unistd.h>

//! Standard exception for polkit
static PyObject *PK_Error;

//! Sets key of dictionary if value is not null
static void
dict_set_unless_null(PyObject *dict, const char *key, const char *value)
{
    if (value != NULL) {
        PyDict_SetItemString(dict, key, PyString_FromString(value));
    }
}

//! Creates action object from action id
static PolKitAction *
pk_make_action(const char *action_id)
{
    PolKitAction *pk_action = polkit_action_new();
    polkit_action_set_action_id(pk_action, action_id);
    return pk_action;
}

//! Creates caller object from uid
static PolKitCaller *
pk_make_caller_from_uid(int uid)
{
    PolKitCaller *pk_caller = polkit_caller_new();
    polkit_caller_set_uid(pk_caller, (uid_t) uid);
    return pk_caller;
}

//! Creates caller object from pid
static PolKitCaller *
pk_make_caller_from_pid(int pid)
{
    PolKitCaller *pk_caller = polkit_caller_new();
    polkit_caller_set_pid(pk_caller, (pid_t) pid);
    return pk_caller;
}

//! Init policy cache
static PolKitPolicyCache *
pk_init_cache()
{
    PolKitError *pk_error = NULL;
    PolKitContext *pk_context = polkit_context_new();

    // Init context
    if (!polkit_context_init(pk_context, &pk_error)) {
        polkit_context_unref(pk_context);
        PyErr_SetString(PK_Error, polkit_error_get_error_name(pk_error));
        return NULL;
    }

    // Load descriptions
    polkit_context_set_load_descriptions(pk_context);

    // Get policy cache
    PolKitPolicyCache *pk_cache = polkit_context_get_policy_cache(pk_context);
    if (pk_cache == NULL) {
        polkit_context_unref(pk_context);
        PyErr_SetString(PK_Error, polkit_error_get_error_name(pk_error));
        return NULL;
    }

    return pk_cache;
}

//! Init auth db
static PolKitAuthorizationDB *
pk_init_authdb()
{
    PolKitContext *pk_context = polkit_context_new();

    // Get auth db
    PolKitAuthorizationDB *pk_auth = polkit_context_get_authorization_db(pk_context);

    return pk_auth;
}

//! Callback function that fills action list.
static polkit_bool_t
pk_action_list_cb(PolKitPolicyCache *policy_cache, PolKitPolicyFileEntry *entry, void *user_data)
{
    // Append entry to the list
    PyList_Append((PyObject*) user_data, PyString_FromString(polkit_policy_file_entry_get_id(entry)));

    // Continue to iterate
    return FALSE;
}

//! Returns a list of actions
static PyObject *
pk_action_list(PyObject *self, PyObject *args)
{
    PolKitPolicyCache *pk_cache = pk_init_cache();
    if (pk_cache == NULL) {
        return NULL;
    }

    PyObject *list = PyList_New(0);
    polkit_policy_cache_foreach(pk_cache, pk_action_list_cb, list);
    return list;
}

//! Callback function that fills annotation list
static polkit_bool_t
pk_action_info_cb(PolKitPolicyFileEntry *policy_file_entry, const char *key, const char *value, void *user_data)
{
    // Append (key, value) tuple to the list
    PyObject *tuple = PyTuple_New(2);
    PyTuple_SetItem(tuple, 0, PyString_FromString(key));
    PyTuple_SetItem(tuple, 1, PyString_FromString(value));
    PyList_Append((PyObject*) user_data, tuple);

    // Continue to iterate
    return FALSE;
}

//! Returns action details
static PyObject *
pk_action_info(PyObject *self, PyObject *args)
{
    const char* action_id;
    if (!PyArg_ParseTuple(args, "s", &action_id)) {
        return NULL;
    }

    PolKitPolicyCache *pk_cache = pk_init_cache();
    if (pk_cache == NULL) {
        return NULL;
    }

    // Get entry
    PolKitPolicyFileEntry* pk_entry = polkit_policy_cache_get_entry_by_id(pk_cache, action_id);

    PyObject *dict = PyDict_New();

    // Description
    dict_set_unless_null(dict, "description", polkit_policy_file_entry_get_action_description(pk_entry));

    // Message
    dict_set_unless_null(dict, "message", polkit_policy_file_entry_get_action_message(pk_entry));

    // Vendor
    dict_set_unless_null(dict, "vendor", polkit_policy_file_entry_get_action_vendor(pk_entry));

    // Vendor URL
    dict_set_unless_null(dict, "vendor_url", polkit_policy_file_entry_get_action_vendor_url(pk_entry));

    // Icon
    dict_set_unless_null(dict, "icon", polkit_policy_file_entry_get_action_icon_name(pk_entry));

    // Annotations
    PyObject *list = PyList_New(0);
    polkit_policy_file_entry_annotations_foreach(pk_entry, pk_action_info_cb, list);
    PyDict_SetItemString(dict, "annotations", list);

    return dict;
}

//! Callback function that fills auth list.
static polkit_bool_t
pk_auth_list_cb(PolKitAuthorizationDB *authdb, PolKitAuthorization *auth, void *user_data)
{
    PyObject *dict = PyDict_New();

    // Authorization type
    PyDict_SetItemString(dict, "type", PyInt_FromLong((long) polkit_authorization_type(auth)));

    // UID
    PyDict_SetItemString(dict, "uid", PyInt_FromLong((long) polkit_authorization_get_uid(auth)));

    // Action ID
    PyDict_SetItemString(dict, "action_id", PyString_FromString(polkit_authorization_get_action_id(auth)));

    // Time of grant
    PyDateTime_IMPORT;
    time_t rawtime = polkit_authorization_get_time_of_grant(auth);
    struct tm *timeinfo = localtime(&rawtime);
    PyDict_SetItemString(dict, "date", PyDateTime_FromDateAndTime(1900 + timeinfo->tm_year, timeinfo->tm_mon, timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec, 0));

    // Append tuple to userlist
    PyList_Append((PyObject*)user_data, dict);

    // Continue to iterate
    return FALSE;
}

//! Returns granted authorizations
static PyObject *
pk_auth_list_uid(PyObject *self, PyObject *args)
{
    int uid;
    if (!PyArg_ParseTuple(args, "i", &uid)) {
        return NULL;
    }

    PolKitAuthorizationDB *pk_auth = pk_init_authdb();
    PolKitError *pk_error = NULL;

    PyObject *list = PyList_New(0);
    polkit_authorization_db_foreach_for_uid(pk_auth, uid, pk_auth_list_cb, list, &pk_error);

    if (polkit_error_is_set(pk_error)) {
        PyErr_SetString(PK_Error, polkit_error_get_error_name(pk_error));
        polkit_error_free(pk_error);
        return NULL;
    }

    return list;
}

//! Returns granted authorizations
static PyObject *
pk_auth_list_all(PyObject *self, PyObject *args)
{
    PolKitAuthorizationDB *pk_auth = pk_init_authdb();
    PolKitError *pk_error = NULL;

    PyObject *list = PyList_New(0);
    polkit_authorization_db_foreach(pk_auth, pk_auth_list_cb, list, &pk_error);

    if (polkit_error_is_set(pk_error)) {
        PyErr_SetString(PK_Error, polkit_error_get_error_name(pk_error));
        polkit_error_free(pk_error);
        return NULL;
    }
    return list;
}

//! Authorize user for the given action a single time
static PyObject *
pk_auth_add(PyObject *self, PyObject *args)
{
    const char* action_id;
    int pid = -1;
    int uid = -1;
    int type = -1;

    if (!PyArg_ParseTuple(args, "sii|i", &action_id, &type, &uid, &pid)) {
        return NULL;
    }

    PolKitAuthorizationDB *pk_auth = pk_init_authdb();

    PolKitAction *pk_action = pk_make_action(action_id);
    PolKitCaller *pk_caller;

    if ((type == POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT || type == POLKIT_AUTHORIZATION_SCOPE_PROCESS) && !pid) {
        PyErr_SetString(PK_Error, "SCOPE_ONE_SHOT and SCOPE_PROCESS types require pid");
        return NULL;
    }

    polkit_bool_t pk_status;

    switch (type) {
        case POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT:
            pk_caller = pk_make_caller_from_pid(pid);
            pk_status = polkit_authorization_db_add_entry_process_one_shot(pk_auth, pk_action, pk_caller, uid);
            break;
        case POLKIT_AUTHORIZATION_SCOPE_PROCESS:
            pk_caller = pk_make_caller_from_pid(pid);
            pk_status = polkit_authorization_db_add_entry_process(pk_auth, pk_action, pk_caller, uid);
            break;
        case POLKIT_AUTHORIZATION_SCOPE_SESSION:
            pk_caller = pk_make_caller_from_uid(uid);
            pk_status = polkit_authorization_db_add_entry_session(pk_auth, pk_action, pk_caller, uid);
            break;
        case POLKIT_AUTHORIZATION_SCOPE_ALWAYS:
            pk_caller = pk_make_caller_from_uid(uid);
            pk_status = polkit_authorization_db_add_entry_always(pk_auth, pk_action, pk_caller, uid);
            break;
        default:
            PyErr_SetString(PK_Error, "Unknown authorization type.");
            return NULL;
    }

    if (pk_status) {
        Py_INCREF(Py_True);
        return Py_True;
    }
    else {
        Py_INCREF(Py_False);
        return Py_False;
    }
}

static PyObject *pk_check_authv(PyObject *self, PyObject *args) {
  pid_t pid = 0;
  char **argv = NULL;
  polkit_uint64_t result;
  PyObject *resultobj = NULL;
  PyObject *obj = NULL ;
  
  if (!PyArg_ParseTuple(args,(char *)"iO:polkit_check_authv",&pid, &obj))
    return NULL;

  /* Check if is a list */
  if (PyList_Check(obj)) {
    int size = PyList_Size(obj);
    int i = 0;
    argv = (char **) malloc((size+1)*sizeof(char *));

    if (!argv) {
      PyErr_SetString(PK_Error, "malloc failed.");
      goto fail;
    }

    for (i = 0; i < size; i++) {
      PyObject *o = PyList_GetItem(obj,i);
      if (PyString_Check(o))
        argv[i] = PyString_AsString(PyList_GetItem(obj,i));
      else {
	PyErr_SetString(PyExc_TypeError,"list must contain strings");
	goto fail;
      }
    }
    argv[i] = NULL;
  } else if (PyTuple_Check(obj)) {
    int size = PyTuple_Size(obj);
    int i = 0;
    argv = (char **) malloc((size+1)*sizeof(char *));
    if (!argv) {
      PyErr_SetString(PK_Error, "malloc failed.");
      goto fail;
    }
    for (i = 0; i < size; i++) {
      PyObject *o = PyTuple_GetItem(obj,i);
      if (PyString_Check(o))
        argv[i] = PyString_AsString(PyTuple_GetItem(obj,i));
      else {
	PyErr_SetString(PyExc_TypeError,"tuple must contain strings");
	goto fail;
      }
    }
    argv[i] = NULL;
  } else {
    PyErr_SetString(PyExc_TypeError,"not a list or tuple");
    goto fail;
  }

  result = (polkit_uint64_t)polkit_check_authv(pid, (char const **)argv);

  resultobj = PyLong_FromUnsignedLong((unsigned long long)(result));

  if (argv)
    free((char *) argv);

  return resultobj;

fail:
  if (argv)
    free((char *) argv);
  return NULL;
}

static PyObject *pk_auth_obtain(PyObject *self, PyObject *args) {
  PyObject *resultobj = NULL;
  char *action_id = NULL ;
  polkit_uint32_t xid = 0;
  pid_t pid = 0;
  DBusError dbus_err;
  polkit_bool_t result;
  PolKitAction *action = NULL;
  
  dbus_error_init(&dbus_err);
  
  if (!PyArg_ParseTuple(args,(char *)"sii:pk_auth_obtain", &action_id, (int *)&xid, (int *)&pid)) 
    return NULL;

  result = (polkit_bool_t)polkit_auth_obtain((char const *)action_id, xid, pid, &dbus_err);
  
  PyObject *l;
  
  if ((result == FALSE) && dbus_error_is_set(&dbus_err)) {
    PolKitResult res;
    char *out_action_id;
    
    if (polkit_dbus_error_parse(&dbus_err, &action, &res) == FALSE) {
      PyErr_SetString(PK_Error, "polkit_dbus_error_parse");
      goto fail;
    }
    
    if (polkit_action_get_action_id(action, &out_action_id) == FALSE)
      goto fail;
    
    l = PyList_New(0);

    if (!l)
      goto fail_clean_action;

    resultobj = l;
    PyList_Append(l, PyString_FromString(out_action_id));
    PyList_Append(l, PyString_FromString(polkit_result_to_string_representation(res)));
    polkit_action_unref(action);
  } 
  else {
    if (result == TRUE) {
      Py_INCREF(Py_True);
      resultobj = Py_True;
    } else {
      Py_INCREF(Py_False);
      resultobj = Py_False;
    }
  }
  
  dbus_error_free(&dbus_err);
  return resultobj;

 fail_clean_action:
  polkit_action_unref(action);
 fail:
  dbus_error_free(&dbus_err);
  return NULL;
}


//! polkit methods
static PyMethodDef polkit_methods[] = {
    {"action_list", (PyCFunction) pk_action_list, METH_NOARGS, "Lists all actions."},
    {"action_info", (PyCFunction) pk_action_info, METH_VARARGS, "Get action details."},
    {"auth_list_uid", (PyCFunction) pk_auth_list_uid, METH_VARARGS, "List granted authorizations for specified UID."},
    {"auth_list_all", (PyCFunction) pk_auth_list_all, METH_NOARGS, "List granted authorizations."},
    {"auth_add", (PyCFunction) pk_auth_add, METH_VARARGS, "Authorize user for the given action."},
    {"check_authv", (PyCFunction) pk_check_authv, METH_VARARGS, "Check authorization for the given action."},
    {"auth_obtain", (PyCFunction) pk_auth_obtain, METH_VARARGS, "Authorize user for the given action."},
    {NULL, NULL, 0, NULL}
};

#ifndef PyMODINIT_FUNC	/* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

static PyMODINIT_FUNC
init_polkit(void)
{
    PyObject *m = Py_InitModule3("_polkit", polkit_methods, "module for querying system-wide policy");

    if (m == NULL)
      return;

    PyModule_AddObject(m, "SCOPE_ONE_SHOT", PyInt_FromLong((long) POLKIT_AUTHORIZATION_SCOPE_PROCESS_ONE_SHOT));
    PyModule_AddObject(m, "SCOPE_PROCESS", PyInt_FromLong((long) POLKIT_AUTHORIZATION_SCOPE_PROCESS));
    PyModule_AddObject(m, "SCOPE_SESSION", PyInt_FromLong((long) POLKIT_AUTHORIZATION_SCOPE_SESSION));
    PyModule_AddObject(m, "SCOPE_ALWAYS", PyInt_FromLong((long) POLKIT_AUTHORIZATION_SCOPE_ALWAYS));

    PyModule_AddObject(m, "TYPE_UID", PyInt_FromLong((long) POLKIT_AUTHORIZATION_TYPE_UID));

    PyModule_AddObject(m, "DB_CAPABILITY_CAN_OBTAIN", PyInt_FromLong((long) POLKIT_AUTHORIZATION_DB_CAPABILITY_CAN_OBTAIN));

    PK_Error = PyErr_NewException("polkit.error", NULL, NULL);
    Py_INCREF(PK_Error);
    PyModule_AddObject(m, "error", PK_Error);
}
