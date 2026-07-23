document.getElementById('scanForm')?.addEventListener('submit',e=>{const b=e.currentTarget.querySelector('button');b.disabled=true;b.textContent='Analyzing security signals…'});
const canvas=document.getElementById('riskChart');
if(canvas&&window.Chart){const c=JSON.parse(canvas.dataset.counts||'{}');new Chart(canvas,{type:'doughnut',data:{labels:['Phishing','Suspicious','Legitimate','Security Test'],datasets:[{data:[c.Phishing||0,c.Suspicious||0,c.Legitimate||0,c['Security Test']||0],backgroundColor:['#ff5264','#f5b844','#38d895','#25d4c8'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{labels:{color:'#91a5bb'}}}}})}

