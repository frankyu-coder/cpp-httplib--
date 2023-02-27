//
//  client.cc
//
//  Copyright (c) 2019 Yuji Hirose. All rights reserved.
//  MIT License
//

#include <httplib.h>
#include <iostream>
#include "pugixml.hpp"

#define CA_CERT_FILE "./ca-bundle.crt"

using namespace std;

struct xml_string_writer : pugi::xml_writer {
  std::string result;
  virtual void write(const void *data, size_t size) {
    result += std::string(static_cast<const char*>(data), size);
  }
};

int main(void) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  httplib::SSLClient cli("localhost", 8080);
  // httplib::SSLClient cli("google.com");
  // httplib::SSLClient cli("www.youtube.com");
  cli.set_ca_cert_path(CA_CERT_FILE);
  cli.enable_server_certificate_verification(true);
#else
  //httplib::Client cli("219.238.169.198", 9002);
  httplib::Client cli("localhost", 8080);
#endif

  pugi::xml_document doc;	   /* 组装发送报文 */
  pugi::xml_document doc_parse; /*解析报文*/
  pugi::xml_node xml_root = doc.append_child("Transaction");
  pugi::xml_node xml_header = xml_root.append_child("Transaction_Header");
  pugi::xml_node TID = xml_header.append_child("TID");
  TID.append_child(pugi::node_cdata).set_value("-");
  pugi::xml_node xml_body = xml_root.append_child("Transaction_Body");
  pugi::xml_node request = xml_body.append_child("request");
  pugi::xml_node MSG_VER = request.append_child("MSG_VER");
  MSG_VER.append_child(pugi::node_cdata).set_value("XBH.DCEP.A.1.0");
  pugi::xml_node TX_CODE = request.append_child("TX_CODE");
  TX_CODE.append_child(pugi::node_cdata).set_value("XBH000501");
  pugi::xml_node APDURespList = request.append_child("APDURespList");
  pugi::xml_node resp = APDURespList.append_child("resp");
#if 0  // for test
  {
	char recvdata[1024] = {0};
    recvdata[0] = 0x00;
    recvdata[1] = 0x00;
    recvdata[2] = 0x00;
    recvdata[3] = 0x7e;
    recvdata[4] = 0x13;
    recvdata[5] = 0x00;
    recvdata[6] = 0x00;
    recvdata[7] = 0x10;
    recvdata[8] = 0x28;
    recvdata[9] = 0x26;

    //string resp_content = {0x00, 0x00, 0x00, 0x7e, 0x13, 0x00, 0x00, 0x10, 0x28, 0x26};
    string resp_content;
    resp_content.resize(11);
	resp_content.assign(recvdata, 10);
    int len = strlen(resp_content.data());
        len = strlen(recvdata);
    //resp.append_child(pugi::node_cdata).set_value((char*)resp_content.data());
    resp.append_child(pugi::node_cdata).set_value(recvdata);
  }
#else
{
  resp.append_child(pugi::node_cdata).set_value("0000007E130000102826028515520815B9D63D82D072B1B60B88CDB85A9EE2855051513D917CEB3291DC067393B9E57598EFA12592B3FF0A4885BC673C66F3709000");
  resp = APDURespList.append_child("resp");
  resp.append_child(pugi::node_cdata).set_value("001");
  resp = APDURespList.append_child("resp");
  resp.append_child(pugi::node_cdata).set_value("002");
  }  
#endif // test end

  xml_string_writer writer;
  doc.save(writer, PUGIXML_TEXT("\t"), pugi::format_default, pugi::encoding_utf8);

  string package_body;

  package_body.append("\n");
  package_body.append(writer.result);

  cout << "package_body=" << package_body.data() << endl;

  //auto res = cli.Post("/ctd/xbh/dcep/v1/", package_body, "text/plain;charset=UTF-8");

  #if 1 // for test
  doc_parse.load_string(package_body.data()); 
  pugi::xml_node resplist = doc_parse.child("Transaction")
                               .child("Transaction_Body")
                               .child("request")
                               .child("APDURespList");

  for (pugi::xml_node resp = resplist.first_child(); resp; resp = resp.next_sibling()) {
    cout << "resp.value()= " << resp.value() << endl;
    cout << "resp.child_value()= " << resp.child_value() << endl;
  }

  #endif

  auto res = cli.Get("/hi");

  if (res) {
    cout << res->status << endl;
    cout << res->get_header_value("Content-Type") << endl;
    cout << res->body << endl;
  } else {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    auto result = cli.get_openssl_verify_result();
    if (result) {
      cout << "verify error: " << X509_verify_cert_error_string(result) << endl;
    }
#endif
  }

  return 0;
}
