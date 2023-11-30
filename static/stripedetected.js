let svgs = document.getElementsByTagName('svg');

for(let i = 0; i < svgs.length; i++){
  let width = svgs[i].getAttribute('width');
  let height = svgs[i].getAttribute('height');
  
  if(width === '33' && height === '15'){
    svgs[i].querySelector('path').setAttribute('d', 'M1735.5 45.5h199c-.17 110.001 0 220.001.5 330 52.74-67.33 121.58-94.33 206.5-81 50.36 8.557 89.86 33.557 118.5 75a476.424 476.424 0 0 0 13 22c13.97 30.562 22.64 62.562 26 96a702.635 702.635 0 0 1 2 40c.5 167.666.67 335.333.5 503h-196c.49-161.356-.01-322.689-1.5-484-3.96-32.636-21.79-52.969-53.5-61-48.35-6.29-86.85 10.043-115.5 49-.5 165.333-.67 330.666-.5 496h-199v-985ZM2388.5 45.5c63-.167 126 0 189 .5 1.16 63.43 1.33 126.93.5 190.5l-1.5 1.5c-62.67.5-125.33.667-188 .5v-193ZM381.5 290.5c23.851.483 47.518 3.316 71 8.5 54.46 16.479 92.626 50.979 114.5 103.5a7.248 7.248 0 0 0 2.5 2c18.106-29.103 40.439-54.436 67-76a551.644 551.644 0 0 1 36.5-21c56.568-22.443 113.235-22.443 170 0 26.08 11.417 47.746 28.417 65 51 27.86 38.677 43.526 82.01 47 130a50092.38 50092.38 0 0 1 1.5 543c-64.571.33-129.071 0-193.5-1a59200.362 59200.362 0 0 0-2-482c-6.75-42.45-31.583-64.117-74.5-65-29.808.932-55.808 11.266-78 31a449.21 449.21 0 0 0-17.5 20l-1 496a9379.47 9379.47 0 0 1-193.5 1c.486-160.018-.014-320.018-1.5-480-5.568-43.894-30.568-66.561-75-68-19.642.659-38.142 5.492-55.5 14.5-2.364 1.962-5.031 3.462-8 4.5a204.294 204.294 0 0 0-31.5 32l-1 496c-66 1.33-132 1.33-198 0-.667-238.667-.667-477.333 0-716a3813.452 3813.452 0 0 1 174.5 0 4.457 4.457 0 0 0 1.5 2 6426.406 6426.406 0 0 0 11.5 73c16.732-23.395 36.399-43.729 59-61 32.162-23.215 68.162-35.382 108-36.5.556-.383.889-.883 1-1.5ZM1335.5 290.5c31.91.244 63.58 3.41 95 9.5 54.22 13.113 100.38 39.613 138.5 79.5 24.25 29.173 43.92 61.173 59 96 27.9 75.039 38.9 152.705 33 233-2.24 68.278-18.24 132.944-48 194-50.34 91.964-128.17 141.8-233.5 149.5-11 .33-22 .67-33 1-132.47 2.76-226.3-55.735-281.5-175.5-26.08-65.778-38.25-134.111-36.5-205-2.17-69.662 9.66-136.662 35.5-201 51.94-117.334 142.44-177.667 271.5-181Zm-7 177c48.19-4.939 84.02 13.394 107.5 55 4.87 11.632 9.54 23.299 14 35 18.51 79.833 17.85 159.5-2 239a804.387 804.387 0 0 1-10 25c-15.48 32.322-40.98 50.822-76.5 55.5-26.47 3.657-51.13-1.009-74-14a115.503 115.503 0 0 1-19.5-16.5 236.378 236.378 0 0 1-12-17c-10.81-21.163-18.15-43.496-22-67-11.67-68.752-9.67-137.086 6-205a468.006 468.006 0 0 1 16-39c10.94-18.274 25.77-32.441 44.5-42.5a224.4 224.4 0 0 1 28-8.5ZM2958.5 290.5c30.45.433 60.78 3.267 91 8.5 85.37 20.117 147.54 68.951 186.5 146.5a22.784 22.784 0 0 1 4 5c15.33 32.67 26.67 66.67 34 102 16.13 85.203 15.13 170.203-3 255-13.02 57.535-38.02 108.869-75 154-43.78 48.28-98.28 77.44-163.5 87.5-43 6-86 6-129 0-46.3-7.72-88.3-25.39-126-53-38.96-32.965-68.79-72.799-89.5-119.5a496.02 496.02 0 0 1-29-101c-11.02-75.897-9.69-151.563 4-227 10.95-50.583 30.62-97.249 59-140 48.38-67.202 114.21-105.369 197.5-114.5a672.268 672.268 0 0 1 38-2c.56-.383.89-.883 1-1.5Zm-6 177c38.3-5.03 69.63 6.97 94 36 16.74 23.666 27.57 49.999 32.5 79a497.73 497.73 0 0 1 6.5 90.5c2.19 48.277-4.64 95.11-20.5 140.5-21.57 48.4-59.07 69.567-112.5 63.5-31.86-3.915-56.02-19.415-72.5-46.5a286.505 286.505 0 0 1-15-35c-11.02-40.229-15.86-81.229-14.5-123-1.91-45.238 4.25-89.238 18.5-132a833.608 833.608 0 0 1 15-30 215.358 215.358 0 0 0 13.5-16c3.63-2.63 6.97-5.63 10-9 13.89-9.124 28.89-15.124 45-18ZM2388.5 313.5c63.04-.33 126.04.004 189 1 1 238.666 1.33 477.332 1 716h-190v-717Z');
    svgs[i].setAttribute('viewBox', '0 0 3300 1500')
  }
}

setInterval(() => {
  let svgs = document.getElementsByTagName('svg');

  for(let i = 0; i < svgs.length; i++){
    let width = svgs[i].getAttribute('width');
    let height = svgs[i].getAttribute('height');
    
    if(width === '33' && height === '15'){
      svgs[i].querySelector('path').setAttribute('d', 'M1735.5 45.5h199c-.17 110.001 0 220.001.5 330 52.74-67.33 121.58-94.33 206.5-81 50.36 8.557 89.86 33.557 118.5 75a476.424 476.424 0 0 0 13 22c13.97 30.562 22.64 62.562 26 96a702.635 702.635 0 0 1 2 40c.5 167.666.67 335.333.5 503h-196c.49-161.356-.01-322.689-1.5-484-3.96-32.636-21.79-52.969-53.5-61-48.35-6.29-86.85 10.043-115.5 49-.5 165.333-.67 330.666-.5 496h-199v-985ZM2388.5 45.5c63-.167 126 0 189 .5 1.16 63.43 1.33 126.93.5 190.5l-1.5 1.5c-62.67.5-125.33.667-188 .5v-193ZM381.5 290.5c23.851.483 47.518 3.316 71 8.5 54.46 16.479 92.626 50.979 114.5 103.5a7.248 7.248 0 0 0 2.5 2c18.106-29.103 40.439-54.436 67-76a551.644 551.644 0 0 1 36.5-21c56.568-22.443 113.235-22.443 170 0 26.08 11.417 47.746 28.417 65 51 27.86 38.677 43.526 82.01 47 130a50092.38 50092.38 0 0 1 1.5 543c-64.571.33-129.071 0-193.5-1a59200.362 59200.362 0 0 0-2-482c-6.75-42.45-31.583-64.117-74.5-65-29.808.932-55.808 11.266-78 31a449.21 449.21 0 0 0-17.5 20l-1 496a9379.47 9379.47 0 0 1-193.5 1c.486-160.018-.014-320.018-1.5-480-5.568-43.894-30.568-66.561-75-68-19.642.659-38.142 5.492-55.5 14.5-2.364 1.962-5.031 3.462-8 4.5a204.294 204.294 0 0 0-31.5 32l-1 496c-66 1.33-132 1.33-198 0-.667-238.667-.667-477.333 0-716a3813.452 3813.452 0 0 1 174.5 0 4.457 4.457 0 0 0 1.5 2 6426.406 6426.406 0 0 0 11.5 73c16.732-23.395 36.399-43.729 59-61 32.162-23.215 68.162-35.382 108-36.5.556-.383.889-.883 1-1.5ZM1335.5 290.5c31.91.244 63.58 3.41 95 9.5 54.22 13.113 100.38 39.613 138.5 79.5 24.25 29.173 43.92 61.173 59 96 27.9 75.039 38.9 152.705 33 233-2.24 68.278-18.24 132.944-48 194-50.34 91.964-128.17 141.8-233.5 149.5-11 .33-22 .67-33 1-132.47 2.76-226.3-55.735-281.5-175.5-26.08-65.778-38.25-134.111-36.5-205-2.17-69.662 9.66-136.662 35.5-201 51.94-117.334 142.44-177.667 271.5-181Zm-7 177c48.19-4.939 84.02 13.394 107.5 55 4.87 11.632 9.54 23.299 14 35 18.51 79.833 17.85 159.5-2 239a804.387 804.387 0 0 1-10 25c-15.48 32.322-40.98 50.822-76.5 55.5-26.47 3.657-51.13-1.009-74-14a115.503 115.503 0 0 1-19.5-16.5 236.378 236.378 0 0 1-12-17c-10.81-21.163-18.15-43.496-22-67-11.67-68.752-9.67-137.086 6-205a468.006 468.006 0 0 1 16-39c10.94-18.274 25.77-32.441 44.5-42.5a224.4 224.4 0 0 1 28-8.5ZM2958.5 290.5c30.45.433 60.78 3.267 91 8.5 85.37 20.117 147.54 68.951 186.5 146.5a22.784 22.784 0 0 1 4 5c15.33 32.67 26.67 66.67 34 102 16.13 85.203 15.13 170.203-3 255-13.02 57.535-38.02 108.869-75 154-43.78 48.28-98.28 77.44-163.5 87.5-43 6-86 6-129 0-46.3-7.72-88.3-25.39-126-53-38.96-32.965-68.79-72.799-89.5-119.5a496.02 496.02 0 0 1-29-101c-11.02-75.897-9.69-151.563 4-227 10.95-50.583 30.62-97.249 59-140 48.38-67.202 114.21-105.369 197.5-114.5a672.268 672.268 0 0 1 38-2c.56-.383.89-.883 1-1.5Zm-6 177c38.3-5.03 69.63 6.97 94 36 16.74 23.666 27.57 49.999 32.5 79a497.73 497.73 0 0 1 6.5 90.5c2.19 48.277-4.64 95.11-20.5 140.5-21.57 48.4-59.07 69.567-112.5 63.5-31.86-3.915-56.02-19.415-72.5-46.5a286.505 286.505 0 0 1-15-35c-11.02-40.229-15.86-81.229-14.5-123-1.91-45.238 4.25-89.238 18.5-132a833.608 833.608 0 0 1 15-30 215.358 215.358 0 0 0 13.5-16c3.63-2.63 6.97-5.63 10-9 13.89-9.124 28.89-15.124 45-18ZM2388.5 313.5c63.04-.33 126.04.004 189 1 1 238.666 1.33 477.332 1 716h-190v-717Z');
      svgs[i].setAttribute('viewBox', '0 0 3300 1500')
    }
  }
}, 1000);

const popup = document.createElement('div');
popup.style.position = 'fixed';
popup.style.top = '20px';
popup.style.right = '10px';
popup.style.width = '200px';
popup.style.padding = '20px';
popup.style.backgroundColor = '#222';
popup.style.borderRadius = '10px';
popup.style.color = 'limegreen';
popup.style.zIndex = 2147483647;
popup.style.fontWeight = 'bold';
popup.style.fontSize = '18px';
popup.style.opacity = 0;
popup.style.transition = 'opacity 0.5s ease-in-out';

const triangle = document.createElement('div');
triangle.style.width = '0';
triangle.style.height = '0';
triangle.style.borderLeft = '10px solid transparent';
triangle.style.borderRight = '10px solid transparent';
triangle.style.borderBottom = '10px solid #222';
triangle.style.position = 'absolute';
triangle.style.top = '-10px';
triangle.style.right = '20px';
popup.appendChild(triangle);

const jesterSVG = 'data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iaXNvLTg4NTktMSI/Pg0KPCEtLSBVcGxvYWRlZCB0bzogU1ZHIFJlcG8sIHd3dy5zdmdyZXBvLmNvbSwgR2VuZXJhdG9yOiBTVkcgUmVwbyBNaXhlciBUb29scyAtLT4NCjxzdmcgZmlsbD0iIzAwMDAwMCIgaGVpZ2h0PSI4MDBweCIgd2lkdGg9IjgwMHB4IiB2ZXJzaW9uPSIxLjEiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIiANCgkgdmlld0JveD0iMCAwIDUxMiA1MTIiIHhtbDpzcGFjZT0icHJlc2VydmUiPg0KPGc+DQoJPGc+DQoJCTxwYXRoIGQ9Ik0zMzcuMTEsMzYwLjM1NmMtMS4wMzUtMS45MTctMi43ODktMy4zNDUtNC44NzctMy45NjhsLTkuNjM3LTIuODc5Yy0yNS42NTgtNy42NjYtNTIuNzY5LDYuOTcyLTYwLjQzNSwzMi42MjkNCgkJCWMtMS4yOTksNC4zNDcsMS4xNzIsOC45MjIsNS41MTgsMTAuMjIxbDkuNjM3LDIuODh2MC4wMDFjNC42MiwxLjM4LDkuMjg3LDIuMDM3LDEzLjg3OSwyLjAzNw0KCQkJYzIwLjkxMiwwLDQwLjI3MS0xMy42MjksNDYuNTU3LTM0LjY2N0MzMzguMzc2LDM2NC41MjMsMzM4LjE0NSwzNjIuMjcyLDMzNy4xMSwzNjAuMzU2eiBNMzA2LjQ4OCwzODAuOTg2DQoJCQljLTcuNTUzLDQuMDc4LTE2LjI0NSw0Ljk3My0yNC40NjgsMi41MTN2MC4wMDFsLTAuNzQ5LTAuMjI0YzcuNDIzLTEyLjEzOCwyMi4zNjMtMTguMjg1LDM2LjYyMS0xNC4wMjdsMC43NTgsMC4yMjcNCgkJCUMzMTUuNzI3LDM3NC4yNzksMzExLjU2OSwzNzguMjQzLDMwNi40ODgsMzgwLjk4NnoiLz4NCgk8L2c+DQo8L2c+DQo8Zz4NCgk8Zz4NCgkJPHBhdGggZD0iTTI0NS41NDUsMzg2LjEzOGMtNy42NjYtMjUuNjU3LTM0Ljc3OS00MC4yOTYtNjAuNDMyLTMyLjYyOWwtOS42MzgsMi44NzljLTIuMDg3LDAuNjIzLTMuODQyLDIuMDUxLTQuODc3LDMuOTY4DQoJCQljLTEuMDM1LDEuOTE3LTEuMjY2LDQuMTY3LTAuNjQyLDYuMjU0YzYuMjg2LDIxLjAzOSwyNS42NDMsMzQuNjY3LDQ2LjU1NiwzNC42NjdjNC41ODksMCw5LjI1OC0wLjY1NywxMy44NzctMi4wMzdsOS42MzgtMi44ODENCgkJCUMyNDQuMzc0LDM5NS4wNiwyNDYuODQ0LDM5MC40ODQsMjQ1LjU0NSwzODYuMTM4eiBNMjI1LjY4NiwzODMuNTAxdi0wLjAwMWMtMTQuMjYsNC4yNi0yOS4xOTgtMS44OS0zNi42MjEtMTQuMDI3bDAuNzQ5LTAuMjIzDQoJCQljMTQuMjU4LTQuMjY0LDI5LjE5OCwxLjg5LDM2LjYyMSwxNC4wMjdMMjI1LjY4NiwzODMuNTAxeiIvPg0KCTwvZz4NCjwvZz4NCjxnPg0KCTxnPg0KCQk8cGF0aCBkPSJNMzA3LjY5MSw0MzcuMzY1Yy0zLjU3LTIuNzk4LTguNzMzLTIuMTc1LTExLjUzMSwxLjM5NmMtOS4xOTcsMTEuNzMyLTIyLjkzOSwxOC4xOTMtMzguNjk0LDE4LjE5M2gtNy4yMjQNCgkJCWMtMTUuOTg4LDAtMjkuODU4LTYuNjI3LTM5LjA1NS0xOC42NmMtMi43NTUtMy42MDQtNy45MTEtNC4yOTMtMTEuNTEzLTEuNTM4Yy0zLjYwNCwyLjc1NS00LjI5Myw3LjkxLTEuNTM5LDExLjUxNA0KCQkJYzEyLjE5NywxNS45NTgsMzEuMTg5LDI1LjExMSw1Mi4xMDYsMjUuMTExaDcuMjI0YzIwLjYwNywwLDM5LjQyMy04LjkyNCw1MS42MjItMjQuNDg1DQoJCQlDMzExLjg4Niw0NDUuMzI2LDMxMS4yNiw0NDAuMTYzLDMwNy42OTEsNDM3LjM2NXoiLz4NCgk8L2c+DQo8L2c+DQo8Zz4NCgk8Zz4NCgkJPHBhdGggZD0iTTUwMi4zNTQsMjEwLjU1OGMtMi45MzYtNi4yNjUtOC4xMzUtMTEuMDEyLTE0LjYzOS0xMy4zNjVjLTQuNDEyLTEuNTk4LTkuMDY3LTEuOTYtMTMuNTYxLTEuMTE1DQoJCQljLTkuOTEzLTE5LjU2Ny0yNC45NjQtMzYuMDYyLTQzLjU4Ny00Ny43MzFjLTE5LjQxLTEyLjE2MS00MS44NTgtMTguNDg3LTY0Ljg1OS0xOC4yODljLTIwLjU4OSwwLjE3NS00MC4zODksNS42MjEtNTcuODI4LDE1LjU0OQ0KCQkJYy02Ljg1Ni0yNy43MDQtMTguNzc0LTUwLjc0OS0zNi4yNTMtNzAuMTY1Yy0xOC42ODgtMjAuNzU3LTQzLjk3Mi0zNy41MjEtNzcuMzAxLTUxLjI0OWMtMS4wNjktMC40NC0yLjE1NS0wLjc1Ny0zLjI0NC0wLjk3OA0KCQkJYy0xLjAxMi05LjU1My03LjMxNy0xOC4xODQtMTYuOTQxLTIxLjY2OWMtMTMuNDI5LTQuODU5LTI4LjMwOCwyLjExMS0zMy4xNjksMTUuNTM4Yy0yLjM1NSw2LjUwNC0yLjAzNiwxMy41MzcsMC44OTksMTkuODAyDQoJCQljMi45MzUsNi4yNjYsOC4xMzQsMTEuMDEzLDE0LjYzOSwxMy4zNjZjMi44NzgsMS4wNDMsNS44NTksMS41NjEsOC44MzEsMS41NjFzNS45MzUtMC41MjcsOC43NzYtMS41NTgNCgkJCWMwLjE1NiwwLjIwNywwLjMwMSwwLjQxOCwwLjQ2NywwLjYyMmMxOC4wODMsMjIuMTUzLDI3LjQwNiw1MC4xMDMsMjYuMjUyLDc4LjcwNGMtMC4yMDUsNS4wNjItMC43NDEsMTAuMDE1LTEuNTgyLDE0LjgyNQ0KCQkJYy0xNi41ODgtOC45OTQtMzUuNDcyLTE0LjE3OS01NS40OTctMTQuMzVjLTIzLjAxMy0wLjE4NS00NS40NSw2LjEyOC02NC44NTksMTguMjg5Yy0xOC44NjcsMTEuODIxLTM0LjA3NiwyOC41ODgtNDMuOTgxLDQ4LjQ4OQ0KCQkJYy0wLjIyMiwwLjQ0Ny0wLjQyMSwwLjktMC42LDEuMzU2Yy0xMS4wMzctMC41MTEtMjEuNjE4LDYuMTM2LTI1LjU3MiwxNy4wNTdjLTIuMzU1LDYuNTA0LTIuMDM1LDEzLjUzNywwLjg5OSwxOS44MDINCgkJCWMyLjkzNCw2LjI2NSw4LjEzNCwxMS4wMTIsMTQuNjM4LDEzLjM2NWMyLjg3OSwxLjA0Myw1Ljg2LDEuNTYxLDguODMyLDEuNTYxYzMuNzQ1LDAsNy40NzktMC44MjQsMTAuOTcxLTIuNDU5DQoJCQljNi4yNjUtMi45MzUsMTEuMDEyLTguMTM0LDEzLjM2Ny0xNC42MzljMS43NTUtNC44NTIsMS45Ni05Ljg5LDAuODgyLTE0LjU3OWMwLjE1LTAuMDkyLDAuMzA0LTAuMTc0LDAuNDUyLTAuMjcyDQoJCQljMTAuNzM4LTcuMDYsMjMuMjM4LTEwLjc5MywzNi4xNTEtMTAuNzkzYzE3LjA0NSwwLDMxLjUxMSw2LjQ5NCw0MS44MzEsMTguNzc3YzguNDkzLDEwLjEwOSwxMy43MjgsMjMuNzI1LDE1LjExMiwzOC45NA0KCQkJYy0xMC41NzcsMC4yODUtMTkuMDk5LDguOTU4LTE5LjA5OSwxOS42MDJ2MzAuMjI3YzAsNy40NDgsNC4xNjksMTMuOTQsMTAuMjk3LDE3LjI2NXY2Ni45MTENCgkJCWMwLDMzLjIzNywxMC41ODEsNjEuNzU1LDMwLjYwMSw4Mi40NzFjMTkuMDUsMTkuNzE0LDQ1LjQwNiwzMC41Nyw3NC4yMTQsMzAuNTdoMTEuOTI0YzI4LjgwOCwwLDU1LjE2NC0xMC44NTYsNzQuMjE0LTMwLjU3DQoJCQljMjAuMDE4LTIwLjcxNiwzMC41OTktNDkuMjMzLDMwLjU5OS04Mi40NzFjMCwwLDAtMTIuMDk3LDAtMTYuNjMzdi0xNi42MzNjMC00LjUzNy0zLjY3Ni04LjIxNC04LjIxNC04LjIxNA0KCQkJYy00LjUzNywwLTguMjE0LDMuNjc2LTguMjE0LDguMjE0YzAsMCwwLDEyLjA5NywwLDE2LjYzM3YxNi42MzNjMCw1Ni44ODQtMzYuMzQ2LDk2LjYxNC04OC4zODYsOTYuNjE0aC0xMS45MjQNCgkJCWMtNTIuMDQxLDAtODguMzg3LTM5LjcyOS04OC4zODctOTYuNjE0di02NC41NDZoMTk3LjIyMmMxMC44MjMsMCwxOS42MjktOC44MDYsMTkuNjI5LTE5LjYzdi0zMC4yMjcNCgkJCWMwLTEwLjYxNy04LjQ3OS0xOS4yNzEtMTkuMDE4LTE5LjU5OWMxLjM5NC0xNS4xOTIsNi42NjYtMjguODAyLDE1LjIxOC0zOC45MjdjMTAuMzg3LTEyLjI5NiwyNC45LTE4Ljc5NSw0MS45Ny0xOC43OTUNCgkJCWMxMi45MTMsMCwyNS40MTMsMy43MzIsMzYuMTUsMTAuNzkzYzAuNzgsMC41MTMsMS41ODYsMC45NTIsMi40MTEsMS4zMTljLTAuMzg5LDQuNDgsMC4zOTgsOS4wMDQsMi4zNTYsMTMuMTg2DQoJCQljMi45MzUsNi4yNjUsOC4xMzQsMTEuMDEyLDE0LjYzOSwxMy4zNjdjMi45MDEsMS4wNDksNS44NjgsMS41NDYsOC43ODksMS41NDZjMTAuNiwwLDIwLjU2OS02LjU1OCwyNC4zOC0xNy4wODYNCgkJCUM1MDUuNjA4LDIyMy44NTcsNTA1LjI4OSwyMTYuODI0LDUwMi4zNTQsMjEwLjU1OHogTTE3NC4wOTcsMjkuNDc2Yy0xLjkzLDQuNjM1LTcuMjQ5LDcuMDUzLTExLjk5Niw1LjMzMg0KCQkJYy0zLjg3Mi0xLjQwMi02LjQ1Ny01LjI3Ni02LjIzOC05LjM5N2MwLjIwNC0zLjgxOSwyLjc1Mi03LjE5Miw2LjM1NC04LjQ1MUMxNjkuNzQ0LDE0LjMyNiwxNzcuMTYzLDIyLjEwNiwxNzQuMDk3LDI5LjQ3NnoNCgkJCSBNNDIuMDA3LDIyNy4yODhjLTAuODYyLDIuMzgtNC4zNjcsNi4zMDMtOC44NDYsNi4yNTRjLTMuOTM1LTAuMDQyLTcuNTUzLTIuNDcxLTguOTMzLTYuMTU1DQoJCQljLTEuMzkxLTMuNzEzLTAuMjY0LTguMDIxLDIuNzcyLTEwLjU2OWMzLjAyMi0yLjUzNiw3LjQzNS0yLjk0MywxMC44NTEtMC45NDJDNDEuNzQ4LDIxOC4xNiw0My41NDgsMjIzLjAyOSw0Mi4wMDcsMjI3LjI4OHoNCgkJCSBNMTQ5LjM0OCwyMTUuNDQ2Yy0xMy41NDQtMTYuMTE4LTMyLjM1Ny0yNC42MzgtNTQuNDEtMjQuNjM4Yy0xNi4xMTEsMC0zMS43MTQsNC42NTctNDUuMTMsMTMuNDY2DQoJCQljLTAuMDU3LTAuMDQ4LTAuMTE0LTAuMDk1LTAuMTcxLTAuMTQyYzguNTU3LTE3LjE4MSwyMS42OTItMzEuNjU2LDM3Ljk4NS00MS44NjVjMTYuNDk3LTEwLjMzNiwzNS41MjgtMTUuNzg3LDU1LjA5Ni0xNS43ODcNCgkJCWMwLjI5OSwwLDAuNjAxLDAuMDAxLDAuOTAxLDAuMDA0YzU2LjIwMSwwLjQ3OSwxMDIuMDI4LDQ2LjcwMSwxMDIuOTk1LDEwMy40MThjLTAuMTM0LDAuNTg5LTAuMjExLDEuMTk5LTAuMjExLDEuODI4djEzLjE5NQ0KCQkJaC03OC4wMjVDMTY2LjkwNCwyNDUuNzk1LDE2MC4yNzcsMjI4LjQ1NiwxNDkuMzQ4LDIxNS40NDZ6IE0zNTkuOTI5LDI4NC41NTV2MzAuMjI3YzAsMS43NjUtMS40MzcsMy4yMDMtMy4yMDIsMy4yMDNIMTUyLjQxDQoJCQljLTEuNzY1LDAtMy4yMDItMS40MzgtMy4yMDItMy4yMDN2LTMwLjIyN2MwLTEuNzY1LDEuNDM3LTMuMjAyLDMuMjAyLTMuMjAyaDguMDY3aDk0LjEzOGgwLjIzNGg5My44ODloNy45ODkNCgkJCUMzNTguNDkzLDI4MS4zNTQsMzU5LjkyOSwyODIuNzksMzU5LjkyOSwyODQuNTU1eiBNNDU5LjYxNywyMDQuMjQ3Yy0xMy40MDYtOC43OTEtMjguOTk0LTEzLjQzOC00NS4wODktMTMuNDM4DQoJCQljLTIyLjA2MSwwLTQwLjkxMSw4LjUxNC01NC41MTksMjQuNjIxYy0xMS4wMDgsMTMuMDMtMTcuNjgyLDMwLjM3NC0xOS4xNjcsNDkuNDk2aC03Ny43NzlWMjUxLjczDQoJCQljMC0zOS45Ni0xOS4zMTMtNzUuNjAyLTQ4Ljk4OC05Ny44MjZjMS43NzItNy41ODcsMi44NDYtMTUuNTE2LDMuMTc2LTIzLjY2MWMxLjMxOC0zMi42MTYtOS4zMTUtNjQuNDkyLTI5LjkzOS04OS43NTUNCgkJCWMtMC4xNTMtMC4xODgtMC4yNzgtMC4zNDktMC4yMDgtMC41OTZjMC4xMDUtMC4xNjQsMC4yMjMtMC4zMTcsMC4zMjUtMC40ODNjMC4yMTItMC4xODgsMC4zODEtMC4xMzUsMC42NDEtMC4wMw0KCQkJYzYwLjczNywyNS4wMTgsOTMuMzgsNjAuOTM0LDEwNS4yMTUsMTE2LjAyOGMtNy41NTcsNS45MTgtMTQuNDgzLDEyLjc4Ny0yMC42MDEsMjAuNTM5Yy0yLjgxLDMuNTYxLTIuMjAxLDguNzI2LDEuMzYsMTEuNTM1DQoJCQljMy41NiwyLjgxLDguNzI2LDIuMjAyLDExLjUzNS0xLjM2YzE5LjY2NC0yNC45MjQsNDguOTIxLTM5LjM3Myw4MC4yNjktMzkuNjM5YzE5Ljg3OS0wLjIyMSwzOS4yNDYsNS4yODcsNTUuOTk2LDE1Ljc4Mg0KCQkJYzE2LjI2NiwxMC4xOTMsMjkuMzg0LDI0LjYzOSwzNy45NDIsNDEuNzgyQzQ1OS43MjgsMjA0LjExMiw0NTkuNjc2LDIwNC4xODIsNDU5LjYxNywyMDQuMjQ3eiBNNDg3LjgwOCwyMjQuNzY5DQoJCQljLTEuNzgsNC45MTItNi4wMyw2Ljg2Ny0xMC40ODIsNi4xMTljLTQuOTE4LTAuODI2LTguNDUtNS41Mi03LjgzNC0xMC40OWMwLjcwNi01LjcwNyw2LjU5My05LjU3NSwxMi4xMDItNy45MzMNCgkJCUM0ODYuNzQzLDIxMy45OTgsNDg5LjY0MiwyMTkuNyw0ODcuODA4LDIyNC43Njl6Ii8+DQoJPC9nPg0KPC9nPg0KPGc+DQoJPGc+DQoJCTxjaXJjbGUgY3g9IjE3Mi41MjkiIGN5PSIyOTkuNjY1IiByPSI3Ljk5NSIvPg0KCTwvZz4NCjwvZz4NCjxnPg0KCTxnPg0KCQk8Y2lyY2xlIGN4PSIyMDQuNjYiIGN5PSIyOTkuNjY1IiByPSI3Ljk5NSIvPg0KCTwvZz4NCjwvZz4NCjxnPg0KCTxnPg0KCQk8Y2lyY2xlIGN4PSIyMzYuODAzIiBjeT0iMjk5LjY2NSIgcj0iNy45OTUiLz4NCgk8L2c+DQo8L2c+DQo8Zz4NCgk8Zz4NCgkJPGNpcmNsZSBjeD0iMjY4Ljk0NSIgY3k9IjI5OS42NjUiIHI9IjcuOTk1Ii8+DQoJPC9nPg0KPC9nPg0KPGc+DQoJPGc+DQoJCTxjaXJjbGUgY3g9IjMwMS4wNzciIGN5PSIyOTkuNjY1IiByPSI3Ljk5NSIvPg0KCTwvZz4NCjwvZz4NCjxnPg0KCTxnPg0KCQk8Y2lyY2xlIGN4PSIzMzMuMjIiIGN5PSIyOTkuNjY1IiByPSI3Ljk5NSIvPg0KCTwvZz4NCjwvZz4NCjwvc3ZnPg==';
const decodedSVG = atob(jesterSVG.split(',')[1]);
const parser = new DOMParser();
const svgDoc = parser.parseFromString(decodedSVG, 'image/svg+xml');
const svgElem = svgDoc.documentElement;
svgElem.style.width = '50%';
svgElem.style.height = '50%';
svgElem.style.display = 'block';
svgElem.style.margin = '0 auto';
svgElem.style.marginBottom = '10px';
svgElem.style.filter = 'invert(53%) sepia(95%) saturate(6300%) hue-rotate(-10deg) brightness(102%) contrast(105%)';

const text = document.createElement('div');
text.textContent = 'Stripe Detected!\nVersion: STRIPEVERSIONHERE';
text.style.textAlign = 'center';
text.style.marginTop = '10px';

popup.appendChild(svgElem);
popup.appendChild(text);

document.body.appendChild(popup);

setTimeout(() => {
  popup.style.opacity = 1;
}, 10);

setTimeout(() => {
  popup.style.opacity = 0;
}, 4000);

setTimeout(() => {
  popup.remove();
}, 5000);