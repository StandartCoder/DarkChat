class Input{
	constructor(input, btn){
		this.input = document.getElementById(input);
		this.btn = document.getElementById(btn);
		
		this.initEventListeners();
	}
	initEventListeners(){
		let obj = this;
		
		this.btn.onclick = function(){
			if(obj.input.value != "" && obj.input.value != null){
				console.log(obj.input.value);
                writeMsg(obj.input.value, "local");
                eel.exposeSendMsg(obj.input.value)
                
				obj.clear();
			}
		}
		
		this.input.addEventListener("keyup", function(event) {
			if (event.keyCode === 13) {
				event.preventDefault();
				obj.btn.click();
			}
		});
	}
	clear(){
		this.input.value = '';
	}
}