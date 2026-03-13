/*
NAU-CYB 221 – Local Port Inspection Tool 
Name: Ubah Victor ikechukwu 
Registration Number: 2024924044
Course Code: NAU-CYB 221
Level: 200l
Department: Cyber Security
Faculty: Physical Science
*/

#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <set>
#include <iomanip>
#include <ctime>
#include <algorithm>
#include <cstdio>     // popen, pclose
#include <cstdlib>

using namespace std;

struct PortRecord {
    string protocol;
    int port;
    string address;
    int pid;
    string process;
    string service;
    string risk;
    string flag;
    string state;
};

const set<uint16_t> SENSITIVE_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389,
    3306, 5432, 8080, 9200, 27017   // common DB/admin ports
};

string get_timestamp() {
    time_t now = time(nullptr);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return string(buf);
}

string trim(const string& str) {
    size_t first = str.find_first_not_of(" \t\r\n");
    if (first == string::npos) return "";
    size_t last = str.find_last_not_of(" \t\r\n");
    return str.substr(first, last - first + 1);
}

map<uint16_t, string> load_services() {
    map<uint16_t, string> svc;
    ifstream f("/etc/services");
    if (!f.is_open()) return svc;

    string line;
    while (getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        stringstream ss(line);
        string name, portproto;
        if (!(ss >> name >> portproto)) continue;

        size_t slash = portproto.find('/');
        if (slash == string::npos) continue;

        try {
            uint16_t p = static_cast<uint16_t>(stoi(portproto.substr(0, slash)));
            if (portproto.find("/tcp") != string::npos || portproto.find("/udp") != string::npos) {
                if (svc.find(p) == svc.end()) svc[p] = name;   // keep first match
            }
        } catch (...) {}
    }
    return svc;
}

vector<PortRecord> get_ports_from_ss() {
    vector<PortRecord> records;
    FILE* pipe = popen("ss -ltnup", "r");          // -l = listening only, -t = tcp, -n = numeric, -u = udp, -p = process
    if (!pipe) {
        cerr << "Error: Cannot run 'ss' command. Install iproute2 (sudo apt install iproute2)\n";
        return records;
    }

    char buffer[1024];
    string line;

    // Skip 2 header lines
    fgets(buffer, sizeof(buffer), pipe);
    fgets(buffer, sizeof(buffer), pipe);

    while (fgets(buffer, sizeof(buffer), pipe)) {
        line = trim(buffer);
        if (line.empty()) continue;

        istringstream iss(line);
        string netid, state, recvq, sendq, local_str, peer_str;

        iss >> netid >> state >> recvq >> sendq >> local_str >> peer_str;

        // Get the rest of the line (users part)
        string users_part;
        getline(iss, users_part);

        string protocol = (netid == "tcp") ? "TCP" : (netid == "udp" ? "UDP" : netid);

        // Parse local address and port
        size_t colon = local_str.rfind(':');
        if (colon == string::npos) continue;

        string addr = local_str.substr(0, colon);
        string port_str = local_str.substr(colon + 1);

        // Handle IPv6 format [::1]:port
        if (!addr.empty() && addr.front() == '[' && addr.back() == ']') {
            addr = addr.substr(1, addr.size() - 2);
        }

        int port = 0;
        try { port = stoi(port_str); } catch (...) { continue; }

        // Extract PID and process name from users:(("name",pid=1234,fd=xx))
        int pid = -1;
        string process_name = "—";
        size_t pid_pos = users_part.find("pid=");
        if (pid_pos != string::npos) {
            pid_pos += 4;
            size_t end = users_part.find_first_of(",)", pid_pos);
            try {
                pid = stoi(users_part.substr(pid_pos, end - pid_pos));
            } catch (...) {}
        }

        size_t name_pos = users_part.find("(\"");
        if (name_pos != string::npos) {
            name_pos += 2;
            size_t name_end = users_part.find("\",", name_pos);
            if (name_end != string::npos) {
                process_name = users_part.substr(name_pos, name_end - name_pos);
            }
        }

        // Service name
        static auto services = load_services();
        string service = (services.find(port) != services.end()) ? services[port] : "—";

        // Risk classification
        string risk = (addr == "127.0.0.1" || addr == "::1") ? "Local-only" : "Exposed";

        // Flag
        string flag = SENSITIVE_PORTS.count(static_cast<uint16_t>(port)) ? "High-Interest" : "Normal";

        records.push_back({protocol, port, addr, pid, process_name, service, risk, flag, state});
    }

    pclose(pipe);
    return records;
}

void print_table(const vector<PortRecord>& records) {
    cout << "\n=== Local Listening Ports Report – " << get_timestamp() << " ===\n\n";

    cout << left
         << setw(6)  << "Proto"
         << setw(7)  << "Port"
         << setw(18) << "Local Address"
         << setw(8)  << "PID"
         << setw(18) << "Process"
         << setw(12) << "Service"
         << setw(12) << "Risk"
         << setw(14) << "Flag"
         << setw(10) << "State"
         << endl;

    cout << string(105, '-') << endl;

    for (const auto& r : records) {
        cout << left
             << setw(6)  << r.protocol
             << setw(7)  << r.port
             << setw(18) << r.address
             << setw(8)  << (r.pid > 0 ? to_string(r.pid) : "—")
             << setw(18) << r.process
             << setw(12) << r.service
             << setw(12) << r.risk
             << setw(14) << r.flag
             << setw(10) << r.state
             << endl;
    }
}

void save_reports(const vector<PortRecord>& records) {
    ofstream txt("ports_report.txt");
    ofstream json("ports_report.json");

    txt << "Local Ports Report – " << get_timestamp() << "\n\n";

    json << "[\n";
    for (size_t i = 0; i < records.size(); ++i) {
        const auto& r = records[i];

        txt << r.protocol << " " << r.port << " | "
            << r.address << " | PID " << (r.pid > 0 ? to_string(r.pid) : "—")
            << " (" << r.process << ") | " << r.service
            << " | " << r.risk << " | " << r.flag << "\n";

        json << "  {\n"
             << "    \"protocol\": \"" << r.protocol << "\",\n"
             << "    \"port\": " << r.port << ",\n"
             << "    \"address\": \"" << r.address << "\",\n"
             << "    \"pid\": " << r.pid << ",\n"
             << "    \"process\": \"" << r.process << "\",\n"
             << "    \"service\": \"" << r.service << "\",\n"
             << "    \"risk\": \"" << r.risk << "\",\n"
             << "    \"flag\": \"" << r.flag << "\",\n"
             << "    \"state\": \"" << r.state << "\"\n"
             << "  }" << (i < records.size() - 1 ? ",\n" : "\n");
    }
    json << "]\n";

    cout << "\nReports saved:\n";
    cout << "   • ports_report.txt\n";
    cout << "   • ports_report.json\n";
}

int main() {
    cout << "NAU-CYB 221 Local Port Scanner (ss-based version)\n";
    cout << "Running with sudo recommended for full process visibility\n\n";

    auto records = get_ports_from_ss();

    if (records.empty()) {
        cout << "No listening ports found or 'ss' command failed.\n";
        return 1;
    }

    // Sort: TCP before UDP, then by port
    sort(records.begin(), records.end(), [](const PortRecord& a, const PortRecord& b) {
        if (a.protocol != b.protocol) return a.protocol < b.protocol;
        return a.port < b.port;
    });

    print_table(records);
    save_reports(records);

    cout << "\nTop 5 ports by security concern:\n";
    for (size_t i = 0; i < records.size() && i < 5; ++i) {
        const auto& r = records[i];
        cout << r.protocol << " " << r.port << " (" << r.service << ") – "
             << r.risk << " / " << r.flag << " → " << r.process
             << (r.pid > 0 ? " (PID " + to_string(r.pid) + ")" : "") << endl;
    }

    cout << "\nDone. Run 'sudo ss -ltnup' manually for even more details.\n";
    return 0;
}
