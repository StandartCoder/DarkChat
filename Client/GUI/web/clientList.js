let clientManager;

class ExternalClientManager{
    constructor(elementToUpdate){
        this.clients = [];
        this.element = elementToUpdate;
    }
    updateClientList(list){
        removeAllChildren(this.element);
        
        this.clients = list;
        
        for(let i = 0; i < this.clients.length; i++){
            let client = document.createElement("p");
            let textNode = document.createTextNode(this.clients[i]);
            
            client.className = "blockListItem";
            client.appendChild(textNode);
            document.getElementById(this.element).appendChild(client);
        }
        this.updateClientNumberLabel();
    }
    updateClientNumberLabel(){
        document.getElementById("clientNumber").innerHTML = "Online (" + (this.clients.length+1) + ")";    
    }
}
    
