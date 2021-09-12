using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace N_m3u8DL_CLI
{
    class ProgressReporter
    {
        private static string speed = "";
        private static string progress = "";

        static object lockThis = new object();
        public static void Report(string progress, string speed)
        {
        }
    }
}
