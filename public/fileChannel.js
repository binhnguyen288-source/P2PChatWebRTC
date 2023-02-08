
class FileChannel {
    fileChannel = null;
    onFile = null;
    constructor(fileChannel, onFile) {
        this.fileChannel = fileChannel;
        
        let file;
        let fileLength = 0;
        let filename = '';
        let receiveBuffer = [];
        this.fileChannel.onmessage = ({data}) => {
            if (fileLength <= 0) {
                const {name, size} = JSON.parse(data);
                filename = name;
                fileLength = parseInt(size);
                file = new Blob();
                receiveBuffer = [];
            }
            else {
                receiveBuffer.push(data);
                if (receiveBuffer.length === 10000) {
                    file = new Blob([file, ...receiveBuffer]);
                    receiveBuffer = [];
                }
                fileLength -= data.byteLength;
                
                if (fileLength === 0) {
                    if (receiveBuffer.length)
                        file = new Blob([file, ...receiveBuffer]);
                    receiveBuffer = [];
                    onFile(new File([file], filename));
                    
                }
            }
        }
    }
    sendFile(blob) {
        const size = blob.size;

        let writtenSize = 0;
        let counter = 0;
        
        const reader = blob.stream().getReader();

        this.fileChannel.send(JSON.stringify({
            name: blob.name,
            size: size
        }));
        const dataChannel = this.fileChannel;
        const readCallback = async ({ done, value: bytes }) => {
            if (done) return;
            const chunk = 16000;
            let ptr = 0;
            writtenSize += bytes.length;
            let sizeLeft = bytes.length;
            let sendResolve;
            const waitSend = new Promise(resolve => sendResolve = resolve);
            const send = () => {

                while (sizeLeft) {
                    if (dataChannel.bufferedAmount > dataChannel.bufferedAmountLowThreshold) {
                        dataChannel.onbufferedamountlow = () => {
                            dataChannel.onbufferedamountlow = null;
                            send();
                        }
                        return;
                    }
                    let sendSize = Math.min(sizeLeft, chunk);
                    dataChannel.send(bytes.subarray(ptr, ptr + sendSize));
                    sizeLeft -= sendSize;
                    ptr += sendSize;
                }
                sendResolve();
            }
            send();
            await waitSend;
            // while (sizeLeft) {
            //     let sendSize = Math.min(sizeLeft, chunk);
            //     this.fileChannel.send(bytes.subarray(ptr, ptr + sendSize));
            //     sizeLeft -= sendSize;
            //     ptr += sendSize;
            //     await new Promise(resolve => setTimeout(resolve, 1));
            // }
            if (counter++ % 30 === 0) {
                console.log(100 * writtenSize / size);
            }
            reader.read().then(readCallback);
        }
        reader.read().then(readCallback);
    }
}

async function sendFile(ev) {
    if (!ev.files[0]) return;
    addMyFile(ev.files[0]);
    if (!peers[currentSelectedPeer].sendFile(ev.files[0]))
        alert("can't connect to peer, maybe he/she is offline?");
}