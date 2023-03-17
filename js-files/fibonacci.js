function input(params) {
    var it = params.iterations || 1;
    var varCurr = 2;
    var varPrev = 1;
    var tmp;
    if(it <= 1){
        varCurr = it;
    }
    for(var i=2; i<it; i++){
        tmp = varCurr;
        varCurr = tmp + varPrev;
        varPrev = tmp; 
    }

    return JSON.stringify({result:  varCurr, iterations: it});
}