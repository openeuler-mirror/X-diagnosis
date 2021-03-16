#!/bin/bash

#Print the usage.
function usage()
{
    echo "This is a debug tool for glibc memory manage, Usage:"
    echo "    memtool show [options]       Show the running process memory distribution"
    echo "    memtool trace [options]      Trace the running process memory leaks"
    echo "Selection of options:"
    echo "    --process, -p                 Process ID"
    echo "    --files, -f                   Path of record files"
    echo "    --exe, -e                     Exe filename with its path"
    echo "    --time, -t                    Time of trace (sec)"
    echo "    --help, -h                    Print this message and then exit"
    echo "Examples:"
    echo "    memtool show -p PID -f path -e filename"
    echo "    memtool trace -p PID -f path -t time"
}

function trace()
{
    local process_id=$1
    local limit_time=$2
    local file=$3

    gdb attach $process_id &> /dev/null << EOF
call setenv("MALLOC_TRACE","$file",1)
call mtrace()
EOF

    if [ $? -eq 0 ];then
        echo "start trace sucessed"
    else
        echo "start trace failed"
        return 1
    fi

    while true
    do
        if [ $limit_time -gt 0 ];then
            echo -n "$limit_time sec remaining"
            sleep 1
            tput rc
            tput ed
            let limit_time--
            if [ ! -d /proc/${process_id} ];then
                echo "Process does not exist."
                return 1
            fi
        else
            break
        fi
    done

    gdb attach $process_id &> /dev/null << EOF
call muntrace()
call unsetenv("MALLOC_TRACE")
EOF

    if [ $? -eq 0 ];then
        echo "stop trace sucessed"
        return 0
    else
        echo "stop trace failed"
        return 1
    fi
}

function mm_trace()
{
    local process_id=-1
    local limit_time=-1
    local file=""

    while [ $# -gt 0 ]
    do
        case "$1" in
        -p|--process)
            shift
           if [ $# -gt 0 ];then
                if [ -d /proc/$1 ];then
                    process_id=$1
                    shift
                else
                    echo "Invalid process id"
                    usage
                    exit 1
                fi
            else
                echo "Missing parameters"
                usage
                exit 1
           fi
            ;;
        -t|--time)
            shift
           if [ $# -gt 0 ];then
                if [ "$1" -gt 0 ] 2>/dev/null ;then
                    limit_time=$1
                    shift
                else
                    echo "Invalid trace time"
                    usage
                    exit 1
               fi
            else
                echo "Missing parameters"
                usage
                exit 1
            fi
            ;;
        -f|--file)
            shift
            if [ $# -gt 0 ];then
                file=$1
                shift
            else
                echo "Missing parameters"
                usage
                exit 1
            fi
            ;;

        *)
            echo "Unrecognized parameters!"
            usage
            exit 1
            ;;
        esac
    done

    if [ $process_id -eq -1 ];then
       echo "Missing Process ID"
       usage
       exit 1
    fi

    if [ $limit_time -eq -1 ];then
        echo "Missing trace time"
       usage
       exit 1
    fi

    if [ -z $file ];then
        echo "Missing trace file"
        usage
        exit 1
    else
        if [ ! -d ${file%/*} ];then
            echo "invalid file path"
            exit 1
        fi
    fi

    trace $process_id $limit_time ${file}-tmp

    if [ -f ${file}-tmp ];then
        touch ${file}
        chmod 600 ${file}
        mtrace ${file}-tmp > $file
        rm -rf ${file}-tmp
    fi

    return 0
}

#Show the running process memory distribution
function show_mm_distribution
{
    local process_id=$1
    local record_path=$2
    local exe_file=$3

    gcore -o $record_path/memtool_show_core $process_id &> /dev/null
    gdb -q $exe_file $record_path/memtool_show_core* >> $record_path/mm_show_result.txt << EOF
set pagination off
set \$gdb_size_bits = 7
set \$gdb_malloc_align_mask = 15
set \$gdb_heap_max_size = 2 * 4 * 1024 * 1024 * sizeof(long)
set \$gdb_loop = 1
set \$gdb_prev_inuse = 0x0000000000000001
define print_arena_distribution
    if \$argc != 1
        help print_arena_distribution
    else
        set \$gdb_arena_addr = (mstate)(\$arg0 + 1)
        if \$gdb_arena_addr == &main_arena
            set \$gdb_top = \$gdb_arena_addr->top
            set \$gdb_top_size = \$gdb_arena_addr->top->mchunk_size &~ \$gdb_size_bits
            set \$gdb_ptr = (unsigned long)\$gdb_top - \$gdb_arena_addr->system_mem + (unsigned long)\$gdb_top_size
        else
            set \$gdb_top = \$arg0->ar_ptr->top
            if \$arg0->ar_ptr != (mstate) (\$arg0 + 1)
                set \$gdb_ptr = (unsigned long)(\$arg0 + 1)
            else
                set \$gdb_ptr = (unsigned long)((mstate)(\$arg0 + 1) + 1)
            end
        end
        set \$gdb_p = (mchunkptr)((\$gdb_ptr + \$gdb_malloc_align_mask) &~ \$gdb_malloc_align_mask)
        set \$loop_stop_flag = 0
        while \$gdb_loop == 1
            if \$loop_stop_flag == 1
                loop_break
            end
            set \$gdb_start_addr = \$gdb_p
            set \$gdb_next_addr = (mchunkptr)((unsigned long)\$gdb_start_addr + \$gdb_start_addr->mchunk_size &~ \$gdb_size_bits)
            set \$gdb_end_addr = \$gdb_start_addr
            set \$gdb_original_use_flag = \$gdb_next_addr->mchunk_size & \$gdb_prev_inuse
            set \$gdb_now_use_flag = \$gdb_next_addr->mchunk_size & \$gdb_prev_inuse
            set \$gdb_chunk_num = 0
            set \$gdb_all_chunk_size = 0
            while \$gdb_now_use_flag == \$gdb_original_use_flag
                set \$gdb_chunk_num = \$gdb_chunk_num + 1
                set \$gdb_all_chunk_size = \$gdb_all_chunk_size + \$gdb_end_addr->mchunk_size &~ \$gdb_size_bits
                set \$gdb_end_addr = \$gdb_next_addr
                if \$gdb_end_addr == \$gdb_top
                   set \$loop_stop_flag = 1
                   loop_break
                end
                if \$gdb_end_addr->mchunk_size == \$gdb_prev_inuse
                    set \$loop_stop_flag = 1
                    loop_break
                end
                set \$gdb_next_addr = (mchunkptr)((unsigned long)\$gdb_next_addr + \$gdb_next_addr->mchunk_size &~ \$gdb_size_bits)
                set \$gdb_now_use_flag = \$gdb_next_addr->mchunk_size & \$gdb_prev_inuse
            end
            printf "%#lx%#20lx%20ld%20ld%10d\n", \$gdb_start_addr, \$gdb_end_addr, \$gdb_chunk_num, \$gdb_all_chunk_size, \$gdb_original_use_flag
            set \$gdb_p = \$gdb_end_addr
        end
    end
end
document print_arena_distribution
Syntax: print_arena_distribution arena_addr
| Print the arena memory distribution.
end

define print_mm_distribution
    if \$argc != 0
        help print_mm_distribution
    else
        set \$gdb_heap = (heap_info*)&main_arena - 1
        set \$gdb_thread_num = 1
        printf "\n"
        printf "\n"
        printf "start addr"
        printf "            end addr"
        printf "           chunk num"
        printf "      all chunk size"
        printf "     is use\n"
        print_arena_distribution \$gdb_heap
        set \$gdb_ar_ptr = main_arena.next
        while \$gdb_ar_ptr != &main_arena
            set \$gdb_thread_num = \$gdb_thread_num + 1
            set \$gdb_heap_ptr = (heap_info *)((unsigned long)\$gdb_ar_ptr->top &~ (\$gdb_heap_max_size - 1))
            while \$gdb_heap_ptr->ar_ptr != (mstate) (\$gdb_heap_ptr + 1)
                print_arena_distribution \$gdb_heap_ptr
                set \$gdb_heap_ptr = \$gdb_heap_ptr->prev
            end
            print_arena_distribution \$gdb_heap_ptr
            set \$gdb_ar_ptr = \$gdb_ar_ptr->next
        end
        printf "Printf memory distribution Successfully !"
    end
end
document print_mm_distribution
Syntax: print_mm_distribution option
       0 -- Print the help message
 nothing -- Print the distribution of memory
end
print_mm_distribution
EOF
    rm -f $record_path/memtool_show_core*
}

function mm_show
{
    local process_id=-1
    local record_path=""
    local exe_file=""

    while [ $# -gt 0 ]
    do
        case "$1" in
        -p|--process)
            shift
            if [ $# -eq 0 ]; then
                echo "Missing process id"
                usage
                exit 1
            else
                if [ "$1" -gt 0 ] 2>/dev/null; then
                    process_id=$1
                    shift
                else
                    echo "Invalid process id!"
                    usage
                    exit 1
                fi
                if [ ! -d /proc/$process_id ]; then
                    echo "Process do not exist!"
                    exit 1
                fi
            fi
            ;;
        -f|--files)
            shift
            if [ $# -eq 0 ]; then
                echo "Missing record path"
                exit 1
            else
                record_path=$1
                if [ ! -d $record_path ]; then
                    echo "$record_path do not exists, please create it"
                    usage
                    exit 1
                fi
                record_path=`echo $record_path | sed "s/\/$//g"`
                shift
            fi
            ;;
        -e|--exe)
            shift
            if [ $# -eq 0 ]; then
                echo "Missing exe filename"
                usage
                exit 1
            else
                exe_file=$1
                if [ ! -f $exe_file ]; then
                    echo "Invalid exe filename"
                    usage
                    exit 1
                fi
                shift
            fi
            ;;
        *)
            echo "Unrecognized parameters!"
            usage
            exit 1
            ;;
        esac
    done

    if [ $process_id -eq -1 ];then
       echo "Missing Process ID"
       usage
       exit 1
    fi

    if [ "$record_path" == "" ];then
       echo "Record path can not be empty!"
       usage
       exit 1
    fi

    if [ "$exe_file" == "" ];then
       echo "Exe filename can not be empty!"
       usage
       exit 1
    fi

    show_mm_distribution $process_id $record_path $exe_file

    return 0
}

#judge whether gdb is installed
which gdb &> /dev/null
if [ $? -ne 0 ]; then
    echo "Can not find gdb on this environment"
    exit 1
fi

#judge whether glibc-debuginfo is installed
if [ ! -a "/usr/lib/debug/sbin/ldconfig.debug" ]; then
    echo "Can not find glibc-debuginfo on this environment"
    exit 1
fi

#judge whether glibc-debugutils is installed
if [ ! -a "/usr/bin/mtrace" ]; then
    echo "Can not find glibc-utils on this environment"
    exit 1
fi

if [ $# -lt 1 ] || [ $# -gt 7 ]; then
    usage
    exit 1
fi

case "$1" in
    show)
       shift
        mm_show "$@"
        exit 0
        ;;
    trace)
       shift
       mm_trace "$@"
        exit 0
        ;;
    -h|--help)
        usage
       exit 0
       ;;
    *)
        echo "Unrecognized options!"
        usage
        exit 1
        ;;
esac

