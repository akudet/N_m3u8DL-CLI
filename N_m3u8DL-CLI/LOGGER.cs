using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace N_m3u8DL_CLI
{
    class LOGGER
    {
        public const int Default = 1;
        public const int Error = 2;
        public const int Warning = 3;

        public static string LOGFILE;
        public static bool STOPLOG = false;
        public static string FindLog(string dir)
        {
            return "";
        }

        public static void InitLog()
        {
        }

        //读写锁机制，当资源被占用，其他线程等待
        static ReaderWriterLockSlim LogWriteLock = new ReaderWriterLockSlim();

        public static void PrintLine(string text, int printLevel = 1)
        {
        }

        public static void WriteLine(string text)
        {
        }

        public static void WriteLineError(string text)
        {
        }

        public static void Show(string text)
        {
        }
    }
}
