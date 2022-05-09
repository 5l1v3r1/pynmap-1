# Copyright (C) 2022, Nathalon

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from sys import argv, exc_info
from time import strftime
from getopt import getopt, GetoptError
from colorama import init, Fore, Back, Style
from nmap import PortScanner, PortScannerYield, PortScannerError, __version__


def version():

    print("+---------------------------------------------------------------------------------+")
    print("| pynmap | Copyright (C) 2022 Nathalon                                            |")
    print("|                                                                                 |")
    print("| This program comes with ABSOLUTELY NO WARRANTY; for details type `show w`.      |")
    print("| This is free software, and you are welcome to redistribute it                   |")
    print("| under certain conditions; type `show c` for details.                            |")
    print("+---------------------------------------------------------------------------------+")

    exit(1)


def usage():

    print("Usage: {0} -s -i 192.168.1.0 -p 21-3306".format(argv[0]))
    print("Usage: {0} --generator-scan 192.168.1.0/30 -p 21-25".format(argv[0]))
    print("Usage: {0} --network-pingsweep 192.168.1.0/30".format(argv[0]))

    print("\nOptions:")

    print("  -V: --version                        Print version number")
    print("  -h: --help                           Print this help summary page")
    print("  -i: --ip                             Enter remote host")
    print("  -p: --ports                          Scan specified ports")
    print("  -s: --scan                           Perform a scan")
    print("  -c: --csv-result                     Print result as CSV")
    print("  -n: --network-pingsweep              Perform network pingsweep")
    print("  -g: --generator-scan                 Progressive scan with generator")
    print("  -r: --read-xml                       Read XML files")
    print("  -x: --xml-output                     Output scan in XML format")

    exit(1)


def pynmap():

    init()

    try:
        nmap = PortScanner()

    except PortScannerError:
        print(Fore.RED + "[!]" + Style.RESET_ALL + " Nmap not found: ({0})".format(exc_info()[0]))
        exit(1)

    else:
        print("------------------------------------------------------------")
        print(Fore.YELLOW + "[i]" + Style.RESET_ALL + " Starting at: ({0}), Version: ({1})".format(strftime("%c"), __version__))
        print("------------------------------------------------------------")

    if scan:
        try:
            nmap.scan(hosts=ip, ports=ports, arguments="-O")

        except PortScannerError as e:
            print(Fore.RED + "[!]" + Style.RESET_ALL + " {0}".format(e))
            print(Fore.RED + "[!]" + Style.RESET_ALL + " Exiting...")

            exit(1)

        print(Fore.YELLOW + "[i]" + Style.RESET_ALL + " Scan Info: ({0})".format(nmap.scaninfo()))
        print(Fore.YELLOW + "[i]" + Style.RESET_ALL + " Scan Stats: ({0})".format(nmap.scanstats()))
        print(Fore.YELLOW + "[i]" + Style.RESET_ALL + " Command Used: ({0})".format(nmap.command_line()))
        print("------------------------------------------------------------")
        print(Fore.RED + "[*]" + Style.RESET_ALL + " (System Info)\n")

        if "osmatch" in nmap[ip]:
            for osmatch in nmap[ip]["osmatch"]:
                print(Fore.GREEN + "[i]" + Style.RESET_ALL + " OsMatch.name : {0}".format(osmatch["name"]))
                print(Fore.GREEN + "[i]" + Style.RESET_ALL + " OsMatch.accuracy : {0}".format(osmatch["accuracy"]))
                print(Fore.GREEN + "[i]" + Style.RESET_ALL + " OsMatch.line : {0}".format(osmatch["line"]))

                if "osclass" in osmatch:
                    for osclass in osmatch["osclass"]:
                        print(Fore.GREEN + "[i]" + Style.RESET_ALL + " OsClass.type : {0}".format(osclass["type"]))
                        print(Fore.GREEN + "[i]" + Style.RESET_ALL + " OsClass.vendor : {0}".format(osclass["vendor"]))
                        print(Fore.GREEN + "[i]" + Style.RESET_ALL + " OsClass.osfamily : {0}".format(osclass["osfamily"]))
                        print(Fore.GREEN + "[i]" + Style.RESET_ALL + " OsClass.osgen : {0}".format(osclass["osgen"]))
                        print(Fore.GREEN + "[i]" + Style.RESET_ALL + " OsClass.accuracy : {0}".format(osclass["accuracy"]))
                        print("------------------------------------------------------------")

        for host in nmap.all_hosts():
            if "mac" in nmap[host]["addresses"]:
                print(Fore.GREEN + "[i]" + Style.RESET_ALL + " MAC Adrress: ({0})".format(nmap[host]["vendor"]))

            print(Fore.GREEN + "[i]" + Style.RESET_ALL + " Host : ({0}) Hostname : ({1})".format(host, nmap[host].hostname()))
            print(Fore.GREEN + "[i]" + Style.RESET_ALL + " State : ({0})".format(nmap[host].state()))

        for proto in nmap[host].all_protocols():
            print(Fore.GREEN + "[i]" + Style.RESET_ALL + " Protocol : ({0})".format(proto))
            print("------------------------------------------------------------")

            lport = nmap[host][proto].keys()

            sorted(lport)

            for port in lport:
                print(Fore.GREEN + "[i]" + Style.RESET_ALL + " Port : ({0}) State : ({1})".format(port, nmap[host][proto][port]["state"]))
                print(Fore.GREEN + "[i]" + Style.RESET_ALL + " Service : ({0})".format(nmap[host][proto][port]["name"]))
                print(Fore.GREEN + "[i]" + Style.RESET_ALL + " Reason : ({0})\n".format(nmap[host][proto][port]["reason"]))

    if csv_result:
        print("------------------------------------------------------------")
        print(Fore.RED + "[*]" + Style.RESET_ALL + " Printing result as CSV: \n")
        print(nmap.csv())

    if network_pingsweep:
        print(Fore.RED + "[*]" + Style.RESET_ALL + " Pingsweeping network: ({0})".format(network_pingsweep))
        print("------------------------------------------------------------")

        nmap = PortScanner()
        nmap.scan(hosts=network_pingsweep, arguments="-n -sP -PE")
        hosts_list = [(x, nmap[x]['status']['state'])for x in nmap.all_hosts()]
        
        for host, status in hosts_list:
            print(Fore.GREEN + "[i]" + Style.RESET_ALL + " ({0}) : ({1})".format(host, status))

        print("------------------------------------------------------------")
        print(Fore.RED + "[*]" + Style.RESET_ALL + " Found ({0}) active hosts!".format(len(hosts_list)))

    if generator_scan:
        nmap = PortScannerYield()

        for progressive_result in nmap.scan(hosts=generator_scan, ports=ports):
            print(Fore.GREEN + "[i]" + Style.RESET_ALL + " ({0})".format(progressive_result))
            print("------------------------------------------------------------")

    if read_xml:
        print(Fore.RED + "[*]" + Style.RESET_ALL + " Reading XML file: ")
        print("------------------------------------------------------------")

        try:
            with open(read_xml, "r") as r:
                data = r.read()
                print(data)

        except FileNotFoundError as e:
            print(Fore.RED + "[!]" + Style.RESET_ALL + " {0}".format(e))

    if xml_output:
        print("------------------------------------------------------------")
        print(Fore.RED + "[*]" + Style.RESET_ALL + " Printing result in XML format: ")
        print("------------------------------------------------------------")
        print(nmap.get_nmap_last_output())

    print("------------------------------------------------------------")
    print(Fore.YELLOW + "[i] " + Style.RESET_ALL + "Finished at: ({0}), Version: ({1})".format(strftime("%c"), __version__))
    print("------------------------------------------------------------")


def main():

    global ip
    ip = ""

    global ports
    ports = ""

    global scan
    scan = ""

    global csv_result
    csv_result = ""

    global network_pingsweep
    network_pingsweep = ""

    global generator_scan
    generator_scan = ""

    global read_xml
    read_xml = ""

    global xml_output
    xml_output = ""

    try:
        opts, args = getopt(argv[1:], "hVi:p:scn:g:r:x", [
            "help", "version", "ip=", "ports=", "scan", "csv-result", "network-pingsweep=", "generator-scan=", "read-xml=", "xml-output"])

    except GetoptError:
        usage()

    else:
        try:
            for opt, arg in opts:
                if opt in ("-V", "--version"): version()
                if opt in ("-h", "--help"): usage()
                if opt in ("-i", "--ip"): ip = arg
                if opt in ("-p", "--ports"): ports = arg
                if opt in ("-s", "--scan"): scan = str
                if opt in ("-c", "--csv-result"): csv_result = str
                if opt in ("-n", "--network-pingsweep"): network_pingsweep = arg
                if opt in ("-g", "--generator-scan"): generator_scan = arg
                if opt in ("-r", "--read-xml"): read_xml = arg
                if opt in ("-x", "--xml-output"): xml_output = str

            try:
                if opt:
                    pynmap()

            except UnboundLocalError:
                pass

                usage()
                
        except KeyError as e:
            print(Fore.RED + "[!]" + Style.RESET_ALL + " {0}".format(e))
            print(Fore.RED + "[!]" + Style.RESET_ALL + " Exiting ..")


if __name__ == '__main__':
        main()
