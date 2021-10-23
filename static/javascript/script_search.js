let input = document.getElementById('searching')

input.addEventListener('keyup', (e)=>{
    if (e.keyCode === 13){
        console.log(e.target.value);
    }
})