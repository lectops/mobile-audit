import 'dart:io';
HttpClient buildClient() {
  final client = HttpClient();
  client.badCertificateCallback = (cert, host, port) => true;
  return client;
}
