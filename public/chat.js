const sendBtn = document.getElementById("send");
const message = document.getElementById("message");
const chatBox = document.querySelector(".chatBox");
const listFriend = document.querySelector(".chatlist");
const friendEmail = document.getElementById("f-email");
const localVideo = document.getElementById("localVideo");
const remoteVideo = document.getElementById("remoteVideo");

let currentSelectedPeer = null;
let friendsMap = {};
const peers = {};
const videoPeers = {};
let objectURLs = [];
let localStream = null;
let currentVideoPeer = null;

async function typeset(code) {
    MathJax.startup.promise = MathJax.startup.promise
        .then(() => MathJax.typesetPromise(code()))
        .catch((err) => console.log('Typeset failed: ' + err.message));
    return MathJax.startup.promise;
}

function addFriend() {
    fetch(`/addFriend?id=${friendEmail.value}`)
    .then(loadFriends);
}

function createDownloadLink(blob) {
    const result = URL.createObjectURL(blob);
    objectURLs.push(result);
    return result;
}

function freeAllLinks() {
    objectURLs.forEach(v => URL.revokeObjectURL(v));
    objectURLs = [];
}

function addMyFile(blob) {
    const outDiv = document.createElement("div");
    const midDiv = document.createElement("div");
    const inDiv = document.createElement("div");
    const pValue = document.createElement("p");
    outDiv.className = "message my_message";
    inDiv.className = "content-my-message";
    const downloadButton = document.createElement('a');
    downloadButton.download = blob.name;
    downloadButton.href = createDownloadLink(blob);
    downloadButton.innerText = blob.name;
    pValue.appendChild(downloadButton);
    inDiv.appendChild(pValue);
    midDiv.appendChild(inDiv);
    outDiv.appendChild(midDiv);
    chatBox.appendChild(outDiv);
}


function addFriendFile(blob) {
    const outDiv = document.createElement("div");
    const midDiv = document.createElement("div");
    const inDiv = document.createElement("div");
    const pValue = document.createElement("p");
    outDiv.className = "message friend_message";
    inDiv.className = "content-friend-message";
    const downloadButton = document.createElement('a');
    downloadButton.download = blob.name;
    downloadButton.href = createDownloadLink(blob);
    downloadButton.innerText = blob.name;
    pValue.appendChild(downloadButton);
    inDiv.appendChild(pValue);
    midDiv.appendChild(inDiv);
    outDiv.appendChild(midDiv);
    chatBox.appendChild(outDiv);
}

async function addMyMsg(value) {
    const outDiv = document.createElement("div");
    const midDiv = document.createElement("div");
    const inDiv = document.createElement("div");
    const pValue = document.createElement("p");
    outDiv.className = "message my_message";
    inDiv.className = "content-my-message";
    pValue.innerText = value;
    await typeset(() => [pValue]);
    inDiv.appendChild(pValue);
    midDiv.appendChild(inDiv);
    outDiv.appendChild(midDiv);
    chatBox.appendChild(outDiv);
}

async function addFriendMsg(value) {
    const outDiv = document.createElement("div");
    const midDiv = document.createElement("div");
    const inDiv = document.createElement("div");
    const pValue = document.createElement("p");
    outDiv.className = "message friend_message";
    inDiv.className = "content-friend-message";
    pValue.innerText = value;
    await typeset(() => [pValue]);
    inDiv.appendChild(pValue);
    midDiv.appendChild(inDiv);
    outDiv.appendChild(midDiv);
    chatBox.appendChild(outDiv);
}




sendBtn.onclick = () => {
    if (peers[currentSelectedPeer].sendMessage(message.value)) {
        addMyMsg(message.value);
    }
    else alert("send message failed, the peer maybe offline");
    message.value = '';
}

message.onkeydown = (ev) => {
    if (ev.key.toUpperCase() === 'ENTER')
        sendBtn.click();
}

function connectTo(id) {
    console.log("Connected to id: ", id);
    currentSelectedPeer = id;
    for (const child of listFriend.children) {
        child.className = 'block';
    }
    document.getElementById("otherProfilePicture").src = friendsMap[id].picture;
    document.getElementById("otherFullname").innerText = friendsMap[id].fullname;
    chatBox.innerHTML = '';
    freeAllLinks();
    peers[id].messages.forEach(({ isMyMessage, message, file }) => {
        if (file) isMyMessage ? addMyFile(file) : addFriendFile(file);
        else isMyMessage ? addMyMsg(message) : addFriendMsg(message);
    });

    const currentState = peers[id].peerConnection.iceConnectionState;

    if (currentState !== "connected") {
        peers[id].createOffer();
    }
    
}


async function loadFriends() {
    const response = await fetch('/getListFriend');
    const {id, fullname, picture, friends} = await response.json();
    document.getElementById("profilePicture").src = picture;
    document.getElementById("my-id").value = id;
    listFriend.innerHTML = '';
    friendsMap = {};
    for (const { id, picture, fullname } of friends) {
        friendsMap[id] = { picture, fullname };
        if (!peers[id]) {
            peers[id] = new RTCWrapper(id);
        }
        if (!videoPeers[id]) {
            videoPeers[id] = new RTCWrapper(id, true);
        }
        listFriend.innerHTML += `<div class="block" onclick="connectTo('${id}');this.className='block active'">
                <div class="imgbx">
                    <img src="${picture}" class="cover">
                </div>
                <div class="details">
                    <div class="listHead">
                        <h4>${fullname}</h4>
                        <p class="time"></p>
                    </div>
                    <div class="message_p">
                        <p id="preview${id}">Click here to chat</p>
                    </div>
                </div>
            </div>`
    }
}

loadFriends();



class SingalingChannel {
    ws = null;
    constructor() {
        this.connect();
    }
    connect() {
        this.ws = new WebSocket("wss://" + window.location.host + ":2345");
        this.ws.onopen = () => {}
        this.ws.onmessage = ({ data }) => {
            //console.log(data);
            const { peerId, message } = JSON.parse(data);
            if (!message || !peerId) return;

            if (message.rejected) {
                if (message.video) {
                    if (currentVideoPeer) {
                        videoPeers[peerId].resetPeer();
                        alert("Peer rejected video");
                    }
                } else peers[peerId].resetPeer();
                return;
            }

            if (message.video) {
                if (currentVideoPeer !== null && currentVideoPeer !== peerId) {
                    this.send({
                        peerId,
                        video: true,
                        rejected: true
                    });
                }
                else {
                    videoPeers[peerId].handleSignal(message, peerId);
                }
            } else if (message) {
                peers[peerId].handleSignal(message);
            }
        }
        this.ws.onerror = err => {
            console.error(err);
            this.ws.close();
        }
        this.ws.onclose = () => {
            console.log("Closed signaling channel");
            setTimeout(() => this.connect(), 200);
        }
    }
    send(msg) {
        
        this.ws.send(JSON.stringify(msg));
    }
}

const signalChannel = new SingalingChannel();

class ChatChannel {
    chatChannel = null;
    constructor(chatChannel, onmessage) {
        this.chatChannel = chatChannel;
        this.chatChannel.onmessage = onmessage;
    }
    sendMessage(message) {
        this.chatChannel.send(message);
    }
}



class RTCWrapper {
    peerConnection = null;
    currentPeerId = null;
    chatChannel = null;
    fileChannel = null;
    messages = null;
    polite = null;
    makingOffer = null;
    videoPeer = null;
    constructor(peerId, videoPeer = false) {
        this.videoPeer = videoPeer;
        this.messages = [];
        this.currentPeerId = peerId;
        this.polite = document.getElementById("my-id").value < peerId;
        this.resetPeer();
    }
    resetPeer() {
        if (this.peerConnection) this.peerConnection.close();
        this.makingOffer = false;
        this.chatChannel = null;
        this.fileChannel = null;
        const peer = new RTCPeerConnection({
            iceServers: [
                { urls:"stun:stun.l.google.com:19302" }, 
                { urls:"stun:stun1.l.google.com:19302" },
                // { urls:"stun:stun2.l.google.com:19302" },
                // { urls:"stun:stun3.l.google.com:19302" }
            ]
        });
        peer.onnegotiationneeded = async () => {
            console.log("negotiation");
            this.makingOffer = true;

            await this.peerConnection.setLocalDescription();
            signalChannel.send({
                peerId: this.currentPeerId,
                description: this.peerConnection.localDescription,
                video: this.videoPeer
            });

            this.makingOffer = false;
        }
        peer.oniceconnectionstatechange = () => {
            switch (peer.iceConnectionState) {
                case 'failed':
                case 'closed':
                case 'disconnected':
                    this.resetPeer();
                    break;
            }
        }
        peer.onsignalingstatechange = () => {};
        peer.ondatachannel = ({channel}) => {
            if (channel.label === "chat") {
                this.chatChannel = new ChatChannel(channel, ({data}) => {
                    this.messages.push({ isMyMessage: false, message: data });
                    document.getElementById(`preview${this.currentPeerId}`).innerText = `They: ${data}`;
                    if (this.currentPeerId === currentSelectedPeer)
                        addFriendMsg(data);
                });
            }
            if (channel.label === "file") {
                channel.binaryType = 'arraybuffer';
                this.fileChannel = new FileChannel(channel, (blob) => {
                    this.messages.push({ isMyMessage: false, file: blob });
                    document.getElementById(`preview${this.currentPeerId}`).innerText = "Sent a file";
                    if (this.currentPeerId === currentSelectedPeer)
                        addFriendFile(blob);
                });
            }
        }
        peer.onicecandidate = ({ candidate }) => {
            //console.log(candidate);
            
            signalChannel.send({
                peerId: this.currentPeerId,
                candidate,
                video: this.videoPeer
            });
        }
        peer.ontrack = (ev) => {
            //console.log(ev);
            remoteVideo.srcObject = ev.streams[0];
        }
        this.peerConnection = peer;
        if (this.videoPeer) {
            document.getElementById("chatWindow").style.display = 'inherit';
            document.getElementById("videoWindow").style.display = 'none';
            if (localStream !== null)
                localStream.getTracks().forEach(track => track.stop());
            localStream = null;
            currentVideoPeer = null;
        }
        
    }
    
    async createOffer() {
        if (this.videoPeer) {
            await openWebcam(this.peerConnection);
        }
        else {
            this.chatChannel = new ChatChannel(
                this.peerConnection.createDataChannel("chat"),
                ({data}) => {
                    this.messages.push({ isMyMessage: false, message: data });
                    document.getElementById(`preview${this.currentPeerId}`).innerText = `They: ${data}`;
                    if (this.currentPeerId === currentSelectedPeer)
                        addFriendMsg(data);
                }
            );

            this.fileChannel = new FileChannel(
                this.peerConnection.createDataChannel("file"), 
                (blob) => {
                    this.messages.push({ isMyMessage: false, file: blob });
                    document.getElementById(`preview${this.currentPeerId}`).innerText = "Sent a file";
                    if (this.currentPeerId === currentSelectedPeer)
                        addFriendFile(blob);
                }
            );
        }
    }


    async handleSignal({ description, candidate }, offerPeer = null) {

   
        if (!description) {
            //console.log(candidate);
            if (this.videoPeer && !currentVideoPeer) {
                //console.log(currentVideoPeer);
                console.log("dropped ice");
                return;
            }
            if (candidate) {
                await this.peerConnection.addIceCandidate(candidate);
            }
            return;
        }
        
        if (this.peerConnection.signalingState !== "have-local-offer" && 
            description.type === "answer") return;

        const offerCollision = 
            description.type === "offer" && 
            (this.makingOffer || this.peerConnection.signalingState !== "stable");

        if (!this.polite && offerCollision) 
            return;

        if (description.type === "offer") {
            this.resetPeer();
            if (this.videoPeer)
                currentVideoPeer = offerPeer;
        }

        await this.peerConnection.setRemoteDescription(description);
        

        if (description.type === "offer") {
            if (this.videoPeer) {
                if (confirm(`Accept call from ${offerPeer}?`)) {

                    await openWebcam(this.peerConnection);
                }
                else {
                    this.resetPeer();
                    currentVideoPeer = null;
                    signalChannel.send({
                        peerId: offerPeer,
                        video: true,
                        rejected: true
                    });
                    return;
                }
            }
            await this.peerConnection.setLocalDescription();
            signalChannel.send({
                peerId: this.currentPeerId,
                description: this.peerConnection.localDescription,
                video: this.videoPeer
            });
        }

    }
    sendMessage(message) {
        if (this.chatChannel?.chatChannel?.readyState === "open") {
           
            document.getElementById(`preview${this.currentPeerId}`).innerText = `You: ${message}`;
            this.messages.push({ isMyMessage: true, message });
            this.chatChannel.sendMessage(message);
            return true;
        }
        this.resetPeer();
        this.createOffer();
        return false;
        
    }
    sendFile(blob) {
        if (this.fileChannel.fileChannel.readyState !== "open") {
            this.resetPeer();
            this.createOffer();
            return false;
        }
        this.messages.push({ isMyMessage: true, file: blob });
        this.fileChannel.sendFile(blob);
        return true;
    }
};


async function openWebcam(peerConnection) {
    if (localStream !== null) return;
    try {
        localStream = await navigator.mediaDevices.getUserMedia({ 
            video: true, audio: true 
        });
        localVideo.srcObject = localStream;
        localStream.getTracks().forEach(track => peerConnection.addTrack(track, localStream));
        document.getElementById("chatWindow").style.display = 'none';
        document.getElementById("videoWindow").style.display = 'grid';
    }
    catch (e) {
        console.error(e);
    }
}

async function startVideoCall() {

    currentVideoPeer = currentSelectedPeer;
    videoPeers[currentSelectedPeer].createOffer();
    
}