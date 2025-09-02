// include libraries that can navigate, read, write, and print what's in
// directories and files also math, and networking  libraries i think (uint#_t,
// ntohs, hston?), arrays and data manipulation
//
// What is the best way to program the following: single large file? few files?
// how does it work with c?
//   `Ask user the name of the file, or if user wants to analyze all files in
//   the directory; Look in current directory for files types '.pcap' and
//   '.pcapng';
//      if file types are absent
//          print 'there are no capture files in this directory';
//          exit();
//      else
//      open file;
//      read file header;
//      print file metadata;
//      loop through all packets in file;
//      progress tracker as program is reading all packets;
//      list all captured ports and protocols;
//      count and print total number of captured IP addresses, ports, and
//      protocols (source and destination); ask user to choose how they want to
//      sort the list: chronologically from first captured to last, IPs with the
//      most port connections to the least,
//          IPs with longest connection duration to the shortest, ports that Tx
//          and Rx the total largest bytes to total the smallest.
//      list all source and destination IPs with their respective source and
//      destination ports and protocols based on how the user specified.; user
//      can change the sorting; close file; end;`
//
