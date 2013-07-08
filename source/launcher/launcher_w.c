/* @ORIGINAL_AUTHOR: Benjamin Kemper */

/*! @file
 *
 * Launcher code for windows.
 *
 * To modify the launcher to launch a specific tool, use the auxiliary function
 * build_user_argv. This function should return an array of the tool specific arguments
 * and their count. These arguments will be added to the pin command line.
 *
 * An example of adding a tool and its 64bit version to the command line arguments is
 * shown in the comment inside build_user_argv.
 *
 */
#include <stdio.h>
#include <process.h>
#include <windows.h>
#include <io.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

/*!
 * Checks the return value of libc calls and prints the correct error message on error.
 * @param r Return value
 * @param s Error message
 */
void check_retval(int retval, const char* str)
{
    if (retval != 0)
    {
        perror(str);
        exit(1);
    }
}

/*!
 * Appends 3 constant null terminated strings.
 * @param s1
 * @param s2
 * @param s3
 * @return The concatenated string
 */
static char* append3(const char* s1, const char* s2, const char* s3)
{
    int n = 1;
    char* p = 0;
    if (s1)
        n += strlen(s1);
    if (s2)
        n += strlen(s2);
    if (s3)
        n += strlen(s3);
    p = (char*) malloc(sizeof(char) * n);
    if (s1)
        strcpy(p, s1);
    if (s2)
        strcat(p, s2);
    if (s3)
        strcat(p, s3);
    return p;
}

/*!
 * @brief Checks if the file exist and readable.
 * @param fn The file path
 * @return True if exist, readable and executable
 */
unsigned int check_file_exists(const char* fn)
{
    unsigned int okay = 1;
    /* printf("Checking for %s\n",fn); */
    if (_access_s(fn, 4) != 0)
        okay = 0;
    return okay;
}

/*!
 * @brief Checks for file properties and prints an error message is requirements are not met.
 * @param fn The file path
 */
void check_file(const char* fn)
{
    unsigned int okay = check_file_exists(fn);
    if (!okay)
    {
        fprintf(stderr, "Error. File doesn't exist.\n\n");
        exit(1);
    }
}

/*!
 * Checks that a file exists in the directory and that it is not a directory.
 * @param fn The file path to be checked
 * @param dir The directory path to be checked in
 * @param buff A buffer to create the complete path
 * @return 1 if file exist and not a directory
 */
unsigned int check_file_in_dir(const char* fn, const char *dir, char *buff)
{
    buff = append3(dir, "\\", fn);
    return check_file_exists(buff);
}

/*!
 * Searches for the given executable in the directories list at the PATH environment variable,
 * and returns the directory it was found in.
 * @param exename The executable path
 * @return The directory it was found in, or null if not found.
 */
char *search_in_path(const char *exename)
{
    const char dirsepchar = ';';

    char *syspath = strdup(getenv("PATH"));
    char *buff = (char*) malloc(strlen(syspath) + strlen(exename) + 2);
    char *dir = syspath;
    char *dirsep = strchr(dir, dirsepchar);
    char *path = 0;
    while (dirsep)
    {
        *dirsep = 0;
        if (check_file_in_dir(exename, dir, buff))
        {
            path = strdup(dir);
            free(syspath);
            free(buff);
            return path;
        }
        dir = dirsep + 1;
        dirsep = strchr(dir, dirsepchar);
    }
    if (check_file_in_dir(exename, dir, buff))
    {
        path = strdup(dir);
    }
    free(syspath);
    free(buff);
    return path;
}

char* stringify_argv_array(char** argv)
{
    int i, len = 0;
    char* output = 0;
    char* t = 0;
    for (i = 0; argv[i]; i++)
    {
        /* the +1 is for the space I add between strings below */
        len += strlen(argv[i]) + 1;
    }

    /* the +1 is for the null */
    output = malloc(sizeof(char) * (len + 1));
    output[0] = 0;
    for (i = 0; argv[i]; i++)
    {
        t = argv[i];

        (void) strcat(output, t);
        if (argv[i + 1])
            (void) strcat(output, " ");
    }

    return output;
}

int create_process(char** child_argv)
{
    STARTUPINFO si, mystartup;
    PROCESS_INFORMATION pi;
    char* command_line;
    __int32 retval;

    memset(&si, 0, sizeof(si));
    memset(&pi, 0, sizeof(pi));
    si.cb = sizeof(si);

    command_line = stringify_argv_array(child_argv);

    if (!CreateProcess(NULL, command_line, NULL, NULL, TRUE, 0, NULL, NULL, &si,
            &pi))
    {
        fprintf(stderr, "PIN ERROR: CreateProcess failed\n");
        exit(1);
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &retval);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return retval;
}

/*!
 * @brief Finds the driver name across links.
 * @param argv0 This executable path
 * @return Resolved path to the executable
 */
char* find_driver_name(char* argv0)
{
    int chars;
    char base_path[MAX_PATH];
    chars = GetModuleFileName(NULL, base_path, MAX_PATH);
    if (chars == 0)
    {
        fprintf(stderr, "ERROR: Could not find base path for Pin driver\n");
        exit(1);
    }
    return strdup(base_path);
}
/*!
 * Finds the base path (containing directory) of the given executable.
 * @param filename The file path
 * @return The base path
 */
char* find_base_path(char* filename)
{
    char* x;
    char* path = strdup(filename);
    x = strrchr(path, '\\');
    if (x)
    {
        *x = 0;
    }
    else
    {
        x = strrchr(path, '/');
        if (x)
        {
            *x = 0;
        }
    }
    return path;
}

int has_quotes(char* s) {
    char* x = strchr(s,'"');
    if (x)
        return 1;
    return 0;
}

char* escape_quotes(char* s) {
    /* add a backslash in front of each quote */
    char* t = s;
    char* p = 0;
    char* q = 0;
    unsigned int quotes = 0;
    unsigned int len  = 0;
    char* output = 0;

    /* count quotes */
    for(p=t; *p; p++) {
        quotes+= (*p == '"');
    }

    /* allocate a large enough string to hold the extra backslashes */
    len = strlen(t);
    output = malloc(sizeof(char)*(quotes+len+1));
    q=output;
    for(p=t; *p; p++) {
        if (*p == '"')
            *q++ = '\\';
        *q++ = *p;
    }
    /* null terminate the output */
    *q = 0;
    return output;
}

char* cond_escape_quotes(char* s) {
    /* if there are quotes in the string, add a backslash in front of them */
    char* t = s;
    if (has_quotes(s))
        t = escape_quotes(t);
    return t;
}

char* escape_back_slashes(char* s) {
    /* first look for n-backslashes followed by a quote -> double all the
     * backslashes before the quote. */
    char* t = s;
    unsigned int i =0;
    unsigned int len = 0;
    unsigned int backslash_count = 0;
    unsigned int total_additions = 0;
    char* output = 0;
    char* q = 0;

    len = strlen(t);

    /* count up how many extra chars we need */
    for(i=0;i<len;i++) {
        if (t[i] == '\\') {
            backslash_count++;
        }
        else if (t[i] == '"') {
            if (backslash_count) {
                /* pretend to emit  2n backslashes then the quote */
                total_additions += backslash_count;
                backslash_count = 0;
            }
        }
        else {
            backslash_count = 0;
        }
    }

    /* make an new string with the extra chars */
    output = malloc(sizeof(char)*(total_additions+len+1));
    q = output;
    backslash_count = 0;
    for(i=0;i<len;i++) {
        if (t[i] == '\\') {
            backslash_count++;
        }
        else if (t[i] == '"') {
            if (backslash_count) {
                unsigned int j;
                /* emit  2n backslashes then the quote */
                for(j=0;j<backslash_count;j++) {
                    *q++ = '\\';
                    *q++ = '\\';
                }
                backslash_count = 0;
            }
            *q++ = '"';
        }
        else {
            /* emit any backslashes we were temporarily delaying */
            unsigned int j;
            for(j=0;j<backslash_count;j++)
                *q++ = '\\';
            *q++ = t[i];
            backslash_count = 0;
        }
    }
    *q = 0;
    return output;
}

char* escape_final_back_slashes(char* s) {

    /* look for a string with a space with a backslash as the last
     * character - > double trailing ending backslashes */
    char* t = s;
    unsigned int len = 0;
    len = strlen(t);
    if (has_spaces(t) && t[len-1] == '\\') {
        char* output = 0;
        char* p = 0;
        char* q = 0;
        char* start_doubling_pos=0;
        int i=0;
        unsigned int slashes=0;

        for(i=(int)(len-1); i>=0; i--) {
            if (t[i] == '\\') {
                start_doubling_pos = t+i;
                slashes++;
            }
            else
                break;
        }
        if (start_doubling_pos) {
            output = malloc(sizeof(char)*(slashes+len+1));
            p = output;
            q = t;
            while(*p) {
                if (q >= start_doubling_pos)
                    *p++ = '\\';
                *p++ = *q++;
            }
            *q = 0;
            return output;
        }
    }


    return t;
}

char* cond_escape_back_slashes(char* s) {
    /* if there are quotes preceeded by backslashes, double the
     * backslashes. Also a trailing backslash in a string with spaces will
     * get a final quote so that backslash must be doubled as well. Given
     * that there were no quotes in the string, it could easily be
     * skipped.

     backslash quote -> backslash backslash quote (and later we'll add one
     before the quote)

     n-backslashes quote -> 2n-backslashes quote (and later we'll add one
     before the quote)

     space any n-backslashes null -> space any 2n-backslashes null (and
                                      we'll add surrounding quotes later
                                      because of the space)

    */

    char* t = s;
    t = escape_back_slashes(t);
    t = escape_final_back_slashes(t);
    return t;
}

int has_spaces(char* s) {
    char* x = strpbrk(s," \t");
    if (x)
        return 1;
    return 0;
}

char* add_quotes(char* s) {
    return append3("\"", s, "\"");
}

char* cond_add_quotes(char* s) {
    if (has_spaces(s))
        return add_quotes(s);
    return strdup(s);
}

char* escape_string(char* s) {
    char* t = s;
    t = cond_escape_back_slashes(t);
    t = cond_escape_quotes(t);
    t = cond_add_quotes(t);
    return t;
}

/*!
 * Builds the command line arguments to be passed to pin.
 * @param argc The original argc
 * @param base_path The path to the kit
 * @param argv The original argv array
 * @return A null terminated array with the required parameters to pin.
 */
char** build_child_argv(char* base_path, int argc, char** argv, int user_argc,
        char** user_argv)
{
    char** child_argv = (char**) malloc(sizeof(char*) * (argc + user_argc + 3));
    int var = 0, user_arg = 0, child_argv_ind = 0;
    /*
     * Since 64bit system can run 32bit executables, we run the 32bit pinbin. If this is a 64bit
     * machine, pinbin will switch to the 64bit version of itself based on the -p64 parameter.
     */
    child_argv[child_argv_ind++] = append3(base_path, "/", "ia32/bin/pin.exe");
    child_argv[child_argv_ind++] = "-p64";
    child_argv[child_argv_ind++] = append3(base_path, "/",
            "intel64/bin/pin.exe");

    /* Add the user arguments */
    for (user_arg = 0; user_arg < user_argc; ++user_arg)
    {
        child_argv[child_argv_ind++] = escape_string(user_argv[user_arg]);
    }

    /* Copy original command line parameters. */
    for (var = 1; var < argc; ++var)
    {
        child_argv[child_argv_ind++] = escape_string(argv[var]);
    }

    /* Null terminate the array. */
    child_argv[child_argv_ind++] = NULL;

    /* Clean the user arguments memory */
    if (user_argv)
    {
        free(user_argv);
    }

    return child_argv;
}

char** build_user_argv(int* argc)
{
    char** argv = NULL;
    /* Usage Example:
     ====================================================
     *argc = 4; // Number of user defined arguments

     argv = (char**) malloc(sizeof(char*) * (*argc));

     argv[0] = "-t";
     argv[1] = append3("path_to_tool", "\\\\", "toolname32");
     argv[2] = "-t64";
     argv[3] = append3("path_to_tool", "\\\\", "toolname64");
     */

    return argv;
}

/*!
 * Prints the command line arguments.
 * @param child_argv Command line arguments array. Must be null terminated.
 */
void print_argv_chunks(char** child_argv)
{
    char** p = child_argv;
    unsigned int i = 0;
    printf("\n");
    while (*p)
    {
        printf("argv[%d] = [%s]\n", i, *p);
        p++;
        i++;
    }
}

int main(int orig_argc, char** orig_argv)
{
    char* path_to_cmd;
    char **child_argv, **user_argv;
    int user_argc = 0;
    int res;
    char* base_path;
    char* driver_name;

    driver_name = find_driver_name(orig_argv[0]);
    base_path = find_base_path(driver_name);

    user_argv = build_user_argv(&user_argc);
    child_argv = build_child_argv(base_path, orig_argc, orig_argv, user_argc,
            user_argv);
    path_to_cmd = child_argv[0];

    /* For debug purposes only */
    /*
    print_argv_chunks(child_argv);
     */

    return create_process(child_argv);
}
