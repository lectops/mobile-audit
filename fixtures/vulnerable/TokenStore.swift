import Foundation
func saveSession(token: String) {
    UserDefaults.standard.set(token, forKey: "session")
    NSLog("token %@", token)
}
