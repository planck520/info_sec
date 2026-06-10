/* ============================================================
   FlashBack GUI — WebGL 波浪粒子背景
   直接复用 ChinaCode_frontend-main GL 组件的 GLSL 着色器
   原生 Three.js（不依赖 R3F），视觉效果完全一致
   ============================================================ */

import * as THREE from 'three';

// ══════════════════════════════════════════════════════════════
// 1. GLSL 工具函数 — 周期噪声（直接复用 ChinaCode utils.ts）
// ══════════════════════════════════════════════════════════════
const periodicNoiseGLSL = /* glsl */ `
  float periodicNoise(vec3 p, float time) {
    float noise = 0.0;
    noise += sin(p.x * 2.0 + time) * cos(p.z * 1.5 + time);
    noise += sin(p.x * 3.2 + time * 2.0) * cos(p.z * 2.1 + time) * 0.6;
    noise += sin(p.x * 1.7 + time) * cos(p.z * 2.8 + time * 3.0) * 0.4;
    noise += sin(p.x * p.z * 0.5 + time * 2.0) * 0.3;
    return noise * 0.3;
  }
`;

// ══════════════════════════════════════════════════════════════
// 2. 生成初始粒子位置（直接复用 ChinaCode simulationMaterial.ts getPlane）
// ══════════════════════════════════════════════════════════════
function getPlane(count, components, size = 512, scale = 1.0) {
  const length = count * components;
  const data = new Float32Array(length);
  for (let i = 0; i < count; i++) {
    const i4 = i * components;
    const x = (i % size) / (size - 1);
    const z = Math.floor(i / size) / (size - 1);
    data[i4 + 0] = (x - 0.5) * 2 * scale;
    data[i4 + 1] = 0;
    data[i4 + 2] = (z - 0.5) * 2 * scale;
    data[i4 + 3] = 1.0;
  }
  return data;
}

// ══════════════════════════════════════════════════════════════
// 3. 主入口
// ══════════════════════════════════════════════════════════════
export function initWebGLBackground(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;

  // ── 参数（ChinaCode leva 默认值）────────────────────────
  const SIZE = 512;          // 粒子网格 512×512 = 262,144 个粒子
  const PLANE_SCALE = 10.0;
  const NOISE_SCALE = 0.6;
  const NOISE_INTENSITY = 0.52;
  const TIME_SCALE = 1.0;
  const SPEED = 1.0;
  const FOCUS = 3.8;
  const APERTURE = 1.79;
  const POINT_SIZE = 10.0;
  const OPACITY = 0.8;
  const REVEAL_DURATION = 3.5;
  const LOOP_PERIOD = 24.0;

  // ── Renderer ──────────────────────────────────────────
  const renderer = new THREE.WebGLRenderer({ canvas, alpha: false, antialias: false });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(window.innerWidth, window.innerHeight);

  // ── 主场景 + 透视相机（与 ChinaCode Canvas camera 一致）─
  const mainScene = new THREE.Scene();
  mainScene.background = new THREE.Color('#000000');

  const camera = new THREE.PerspectiveCamera(
    50, window.innerWidth / window.innerHeight, 0.01, 300
  );
  camera.position.set(
    1.2629783123314589,
    2.664606471394044,
    -1.8178993743288914
  );
  camera.lookAt(0, 0, 0);  // R3F 默认 lookAt 原点

  // ── 模拟场景 + 正交相机（GPU 粒子物理计算）────────────
  const simScene = new THREE.Scene();
  const simCamera = new THREE.OrthographicCamera(
    -1, 1, 1, -1, 1 / Math.pow(2, 53), 1
  );

  // ── FBO（帧缓冲对象）— GPU 模拟输出目标 ─────────────
  const fbo = new THREE.WebGLRenderTarget(SIZE, SIZE, {
    minFilter: THREE.NearestFilter,
    magFilter: THREE.NearestFilter,
    format: THREE.RGBAFormat,
    type: THREE.FloatType,
  });

  // ── 初始位置纹理 ─────────────────────────────────────
  const posData = getPlane(SIZE * SIZE, 4, SIZE, PLANE_SCALE);
  const positionsTexture = new THREE.DataTexture(
    posData, SIZE, SIZE, THREE.RGBAFormat, THREE.FloatType
  );
  positionsTexture.needsUpdate = true;

  // ══════════════════════════════════════════════════════════
  // SimulationMaterial — GPU 噪声位移模拟
  // （GLSL 直接复用 ChinaCode simulationMaterial.ts）
  // ══════════════════════════════════════════════════════════
  const simMaterial = new THREE.ShaderMaterial({
    vertexShader: /* glsl */ `
      varying vec2 vUv;
      void main() {
        vUv = uv;
        gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
      }
    `,
    fragmentShader: /* glsl */ `
      uniform sampler2D positions;
      uniform float uTime;
      uniform float uNoiseScale;
      uniform float uNoiseIntensity;
      uniform float uTimeScale;
      uniform float uLoopPeriod;
      varying vec2 vUv;
      ${periodicNoiseGLSL}
      void main() {
        vec3 originalPos = texture2D(positions, vUv).rgb;
        float continuousTime = uTime * uTimeScale * (6.28318530718 / uLoopPeriod);
        vec3 noiseInput = originalPos * uNoiseScale;
        float displacementX = periodicNoise(noiseInput + vec3(0.0, 0.0, 0.0), continuousTime);
        float displacementY = periodicNoise(noiseInput + vec3(50.0, 0.0, 0.0), continuousTime + 2.094);
        float displacementZ = periodicNoise(noiseInput + vec3(0.0, 50.0, 0.0), continuousTime + 4.188);
        vec3 distortion = vec3(displacementX, displacementY, displacementZ) * uNoiseIntensity;
        vec3 finalPos = originalPos + distortion;
        gl_FragColor = vec4(finalPos, 1.0);
      }
    `,
    uniforms: {
      positions: { value: positionsTexture },
      uTime: { value: 0 },
      uNoiseScale: { value: NOISE_SCALE },
      uNoiseIntensity: { value: NOISE_INTENSITY },
      uTimeScale: { value: TIME_SCALE },
      uLoopPeriod: { value: LOOP_PERIOD },
    },
  });

  // 模拟用全屏四边形
  const simGeo = new THREE.BufferGeometry();
  simGeo.setAttribute('position', new THREE.Float32BufferAttribute([
    -1, -1, 0,  1, -1, 0,  1, 1, 0,
    -1, -1, 0,  1, 1, 0,  -1, 1, 0,
  ], 3));
  simGeo.setAttribute('uv', new THREE.Float32BufferAttribute([
    0, 1,  1, 1,  1, 0,
    0, 1,  1, 0,  0, 0,
  ], 2));
  simScene.add(new THREE.Mesh(simGeo, simMaterial));

  // ══════════════════════════════════════════════════════════
  // DofPointsMaterial — 景深粒子渲染
  // （GLSL 直接复用 ChinaCode pointMaterial.ts）
  // ══════════════════════════════════════════════════════════
  const pointMaterial = new THREE.ShaderMaterial({
    vertexShader: /* glsl */ `
      uniform sampler2D positions;
      uniform sampler2D initialPositions;
      uniform float uFocus;
      uniform float uFov;
      uniform float uBlur;
      uniform float uPointSize;
      varying float vDistance;
      varying float vPosY;
      varying vec3 vWorldPosition;
      varying vec3 vInitialPosition;
      void main() {
        vec3 pos = texture2D(positions, position.xy).xyz;
        vec3 initialPos = texture2D(initialPositions, position.xy).xyz;
        vec4 mvPosition = modelViewMatrix * vec4(pos, 1.0);
        gl_Position = projectionMatrix * mvPosition;
        vDistance = abs(uFocus - -mvPosition.z);
        vPosY = pos.y;
        vWorldPosition = pos;
        vInitialPosition = initialPos;
        gl_PointSize = max(vDistance * uBlur * uPointSize, 3.0);
      }
    `,
    fragmentShader: /* glsl */ `
      uniform float uOpacity;
      uniform float uRevealFactor;
      uniform float uRevealProgress;
      uniform float uTime;
      varying float vDistance;
      varying float vPosY;
      varying vec3 vWorldPosition;
      varying vec3 vInitialPosition;
      uniform float uTransition;
      ${periodicNoiseGLSL}

      float sparkleNoise(vec3 seed, float time) {
        float hash = sin(seed.x * 127.1 + seed.y * 311.7 + seed.z * 74.7) * 43758.5453;
        hash = fract(hash);
        float slowTime = time * 1.0;
        float sparkle = 0.0;
        sparkle += sin(slowTime + hash * 6.28318) * 0.5;
        sparkle += sin(slowTime * 1.7 + hash * 12.56636) * 0.3;
        sparkle += sin(slowTime * 0.8 + hash * 18.84954) * 0.2;
        float hash2 = sin(seed.x * 113.5 + seed.y * 271.9 + seed.z * 97.3) * 37849.3241;
        hash2 = fract(hash2);
        float sparkleMask = sin(hash2 * 6.28318) * 0.7;
        sparkleMask += sin(hash2 * 12.56636) * 0.3;
        if (sparkleMask < 0.3) { sparkle *= 0.05; }
        float normalizedSparkle = (sparkle + 1.0) * 0.5;
        float smoothCurve = pow(normalizedSparkle, 4.0);
        float blendFactor = normalizedSparkle * normalizedSparkle;
        float finalBrightness = mix(normalizedSparkle, smoothCurve, blendFactor);
        return 0.7 + finalBrightness * 1.3;
      }

      float sdCircle(vec2 p, float r) {
        return length(p) - r;
      }

      void main() {
        vec2 cxy = 2.0 * gl_PointCoord - 1.0;
        float sdf = sdCircle(cxy, 0.5);
        if (sdf > 0.0) discard;

        float distanceFromCenter = length(vWorldPosition.xz);
        float noiseValue = periodicNoise(vInitialPosition * 4.0, 0.0);
        float revealThreshold = uRevealFactor + noiseValue * 0.3;
        float revealMask = 1.0 - smoothstep(revealThreshold - 0.2, revealThreshold + 0.1, distanceFromCenter);

        float sparkleBrightness = sparkleNoise(vInitialPosition, uTime);
        float alpha = (1.04 - clamp(vDistance, 0.0, 1.0))
                    * clamp(smoothstep(-0.5, 0.25, vPosY), 0.0, 1.0)
                    * uOpacity
                    * revealMask
                    * uRevealProgress
                    * sparkleBrightness;

        gl_FragColor = vec4(vec3(1.0), mix(alpha, sparkleBrightness - 1.1, uTransition));
      }
    `,
    uniforms: {
      positions: { value: null },
      initialPositions: { value: positionsTexture },
      uTime: { value: 0 },
      uFocus: { value: FOCUS },
      uFov: { value: 50 },
      uBlur: { value: APERTURE },
      uTransition: { value: 0.0 },
      uPointSize: { value: POINT_SIZE },
      uOpacity: { value: OPACITY },
      uRevealFactor: { value: 0.0 },
      uRevealProgress: { value: 0.0 },
    },
    transparent: true,
    depthWrite: false,
  });

  // ── 262,144 个粒子 ──────────────────────────────────
  const particleCount = SIZE * SIZE;
  const particlePositions = new Float32Array(particleCount * 3);
  for (let i = 0; i < particleCount; i++) {
    const i3 = i * 3;
    particlePositions[i3 + 0] = (i % SIZE) / SIZE;
    particlePositions[i3 + 1] = i / SIZE / SIZE;
  }
  const particleGeo = new THREE.BufferGeometry();
  particleGeo.setAttribute('position', new THREE.Float32BufferAttribute(particlePositions, 3));
  mainScene.add(new THREE.Points(particleGeo, pointMaterial));

  // ══════════════════════════════════════════════════════════
  // 渲染循环
  // ══════════════════════════════════════════════════════════
  const clock = new THREE.Clock();
  let revealStartTime = null;

  function animate() {
    requestAnimationFrame(animate);

    const elapsed = clock.getElapsedTime();

    // ── Pass 1: GPU 粒子物理模拟 → FBO ──────────────
    renderer.setRenderTarget(fbo);
    renderer.clear();
    simMaterial.uniforms.uTime.value = elapsed;
    simMaterial.uniforms.uNoiseScale.value = NOISE_SCALE;
    simMaterial.uniforms.uNoiseIntensity.value = NOISE_INTENSITY;
    simMaterial.uniforms.uTimeScale.value = TIME_SCALE * SPEED;
    renderer.render(simScene, simCamera);
    renderer.setRenderTarget(null);

    // ── 更新粒子材质 ─────────────────────────────────
    pointMaterial.uniforms.positions.value = fbo.texture;
    pointMaterial.uniforms.uTime.value = elapsed;
    pointMaterial.uniforms.uFocus.value = FOCUS;
    pointMaterial.uniforms.uBlur.value = APERTURE;
    pointMaterial.uniforms.uPointSize.value = POINT_SIZE;
    pointMaterial.uniforms.uOpacity.value = OPACITY;

    // ── Reveal 动画 ──────────────────────────────────
    if (revealStartTime === null) revealStartTime = elapsed;
    const revealElapsed = elapsed - revealStartTime;
    const rawProgress = Math.min(revealElapsed / REVEAL_DURATION, 1.0);
    const easedProgress = 1 - Math.pow(1 - rawProgress, 3);
    pointMaterial.uniforms.uRevealFactor.value = easedProgress * 4.0;
    pointMaterial.uniforms.uRevealProgress.value = easedProgress;

    // ── Pass 2: 粒子渲染 → 屏幕 ─────────────────────
    renderer.render(mainScene, camera);
  }

  // ══════════════════════════════════════════════════════════
  // Resize
  // ══════════════════════════════════════════════════════════
  function onResize() {
    const w = window.innerWidth;
    const h = window.innerHeight;
    renderer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  window.addEventListener('resize', onResize);

  // ══════════════════════════════════════════════════════════
  animate();
}
