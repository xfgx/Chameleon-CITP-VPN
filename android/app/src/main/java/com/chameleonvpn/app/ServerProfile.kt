package com.chameleonvpn.app
// Public node metadata plus this installation's personal encrypted-at-rest profile.
data class ServerProfile(val id:String,val name:String,val mode:String,val addr:String,val pubkey:String="",val subtitle:String="",val ksKey:String="",val inner:String="",val peerInner:String="")
