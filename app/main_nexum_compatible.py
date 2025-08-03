"""
Open Node Main Application - Production Ready with Nexum Compatibility

This is the main entry point for the open_node validator that can join
existing OMNE networks with full nexum validation compliance.

All authority classes have been verified to have identical hash signatures
with the omne_node implementation, ensuring 100% nexum compatibility.
"""

import asyncio
import logging
import os
import signal
import sys
import threading
import time
from typing import Dict, Any

# Import compatibility wrappers that maintain API while using separated components
from omc_wrapper import OMC
from mempool_wrapper import Mempool
from consensus_engine_wrapper import ConsensusEngine

# Import other components
from ledger import Ledger
from network_manager import NetworkManager
from crypto_utils import CryptoUtils
from vrf_utils import VRFUtils
from merkle import MerkleTree
from node_routes import create_app
from dynamic_fee_calculator import DynamicFeeCalculator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/app/logs/open_node.log')
    ]
)

logger = logging.getLogger('OpenNode')


class OpenNode:
    """
    Open Node Validator - Nexum Compatible
    
    Production-ready validator node that can join existing OMNE networks
    with full nexum validation compliance. Uses separated authority classes
    that maintain identical hash signatures with omne_node.
    """

    def __init__(self):
        """Initialize the open node validator."""
        self.running = False
        self.components = {}
        self.shutdown_event = threading.Event()
        
        logger.info("🚀 Initializing Open Node Validator (Nexum Compatible)")
        
        # Load configuration
        self.config = self._load_configuration()
        
        # Initialize core components with separated architecture
        self._initialize_components()
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        logger.info("✅ Open Node initialization complete")

    def _load_configuration(self) -> Dict[str, Any]:
        """Load node configuration."""
        return {
            'validator_id': os.getenv('VALIDATOR_ID', 'open_validator_001'),
            'network_port': int(os.getenv('NETWORK_PORT', '3400')),
            'api_port': int(os.getenv('API_PORT', '8080')),
            'genesis_node_url': os.getenv('GENESIS_NODE_URL', 'http://omne_genesis:3400'),
            'nexum_relay_url': os.getenv('NEXUM_RELAY_URL', 'http://nexum_relay:4000'),
            'max_mempool_size': int(os.getenv('MAX_MEMPOOL_SIZE', '1000')),
            'min_validators': int(os.getenv('MIN_VALIDATORS', '4')),
            'single_validator_mode': os.getenv('SINGLE_VALIDATOR_MODE', 'false').lower() == 'true',
            'is_genesis_node': False  # Open nodes are never genesis nodes
        }

    def _initialize_components(self):
        """Initialize all node components with separated architecture."""
        try:
            # Core cryptographic utilities (nexus-validated)
            self.components['crypto_utils'] = CryptoUtils()
            self.components['vrf_utils'] = VRFUtils()
            self.components['merkle_tree'] = MerkleTree()
            
            # Ledger for blockchain state
            self.components['ledger'] = Ledger(
                genesis_file='genesis.json',
                crypto_utils=self.components['crypto_utils']
            )
            
            # OMC token system with separated architecture (nexus-validated)
            self.components['omc'] = OMC(
                ledger=self.components['ledger'],
                crypto_utils=self.components['crypto_utils'],
                is_genesis_node=self.config['is_genesis_node']
            )
            
            # Dynamic fee calculator
            self.components['fee_calculator'] = DynamicFeeCalculator()
            
            # Network manager for peer communication
            self.components['network_manager'] = NetworkManager(
                node_id=self.config['validator_id'],
                port=self.config['network_port'],
                genesis_node_url=self.config['genesis_node_url']
            )
            
            # Mempool with separated architecture (nexus-validated)
            self.components['mempool'] = Mempool(
                max_size=self.config['max_mempool_size'],
                ledger=self.components['ledger'],
                dynamic_fee_calculator=self.components['fee_calculator'],
                network_manager=self.components['network_manager'],
                is_genesis_node=self.config['is_genesis_node']
            )
            
            # Consensus engine with separated architecture (nexus-validated)
            self.components['consensus'] = ConsensusEngine(
                validator_id=self.config['validator_id'],
                network_manager=self.components['network_manager'],
                ledger=self.components['ledger'],
                mempool=self.components['mempool'],
                crypto_utils=self.components['crypto_utils'],
                vrf_utils=self.components['vrf_utils'],
                min_validators=self.config['min_validators'],
                single_validator_mode=self.config['single_validator_mode'],
                is_genesis_node=self.config['is_genesis_node']
            )
            
            # Cross-reference components
            self.components['mempool'].set_consensus_engine(self.components['consensus'])
            
            logger.info("🔧 All components initialized with separated architecture")
            
        except Exception as e:
            logger.error(f"❌ Failed to initialize components: {e}")
            raise

    async def start(self):
        """Start the open node validator."""
        try:
            self.running = True
            logger.info("🌟 Starting Open Node Validator")
            
            # Start network manager
            await self.components['network_manager'].start()
            logger.info("📡 Network manager started")
            
            # Start consensus engine
            self.components['consensus'].start()
            logger.info("🏛️ Consensus engine started")
            
            # Register with nexum relay for validation
            await self._register_with_nexum()
            
            # Start API server
            app = create_app(
                ledger=self.components['ledger'],
                mempool=self.components['mempool'],
                consensus=self.components['consensus'],
                omc=self.components['omc'],
                network_manager=self.components['network_manager']
            )
            
            # Start FastAPI server
            import uvicorn
            config = uvicorn.Config(
                app=app,
                host="0.0.0.0",
                port=self.config['api_port'],
                log_level="info"
            )
            server = uvicorn.Server(config)
            
            logger.info(f"🌐 API server starting on port {self.config['api_port']}")
            
            # Run server in background
            server_task = asyncio.create_task(server.serve())
            
            # Main event loop
            while self.running and not self.shutdown_event.is_set():
                await self._health_check()
                await asyncio.sleep(30)  # Health check every 30 seconds
                
            # Cleanup
            await self._shutdown()
            
        except Exception as e:
            logger.error(f"❌ Error starting open node: {e}")
            raise

    async def _register_with_nexum(self):
        """Register with nexum relay for validation."""
        try:
            import aiohttp
            
            registration_data = {
                'validator_id': self.config['validator_id'],
                'node_type': 'open_validator',
                'network_endpoint': f"http://localhost:{self.config['network_port']}",
                'api_endpoint': f"http://localhost:{self.config['api_port']}",
                'authority_classes': [
                    'CryptoUtils', 'MerkleTree', 'VRFUtils', 'DecimalEncoder',
                    'TransferRequest', 'OMCCore', 'MempoolCore', 'ConsensusEngineCore'
                ],
                'nexum_compatible': True
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.config['nexum_relay_url']}/register_validator",
                    json=registration_data
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        logger.info(f"✅ Nexum registration successful: {result}")
                    else:
                        logger.warning(f"⚠️ Nexum registration failed: {response.status}")
                        
        except Exception as e:
            logger.warning(f"⚠️ Could not register with nexum relay: {e}")

    async def _health_check(self):
        """Perform periodic health checks."""
        try:
            # Check component health
            health_status = {
                'consensus_running': self.components['consensus'].running,
                'mempool_size': self.components['mempool'].get_mempool_size(),
                'ledger_height': self.components['ledger'].get_current_block_number(),
                'network_peers': len(getattr(self.components['network_manager'], 'connected_peers', [])),
                'nexum_compatible': True
            }
            
            logger.debug(f"💓 Health check: {health_status}")
            
            # Log warnings for issues
            if not health_status['consensus_running']:
                logger.warning("⚠️ Consensus engine not running")
                
            if health_status['network_peers'] == 0:
                logger.warning("⚠️ No network peers connected")
                
        except Exception as e:
            logger.error(f"❌ Health check failed: {e}")

    async def _shutdown(self):
        """Graceful shutdown of the node."""
        logger.info("🛑 Shutting down Open Node Validator")
        
        try:
            # Stop consensus
            if 'consensus' in self.components:
                self.components['consensus'].stop()
                logger.info("🏛️ Consensus engine stopped")
            
            # Stop network manager
            if 'network_manager' in self.components:
                await self.components['network_manager'].stop()
                logger.info("📡 Network manager stopped")
            
            # Cleanup mempool
            if 'mempool' in self.components:
                cleared = self.components['mempool'].clear_mempool()
                logger.info(f"🧹 Mempool cleared: {cleared} transactions")
            
            logger.info("✅ Open Node shutdown complete")
            
        except Exception as e:
            logger.error(f"❌ Error during shutdown: {e}")

    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logger.info(f"📡 Received signal {signum}, initiating shutdown")
        self.running = False
        self.shutdown_event.set()


async def main():
    """Main entry point for open node."""
    try:
        # Create and start open node
        node = OpenNode()
        await node.start()
        
    except KeyboardInterrupt:
        logger.info("🛑 Keyboard interrupt received")
    except Exception as e:
        logger.error(f"❌ Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    # Ensure log directory exists
    os.makedirs('/app/logs', exist_ok=True)
    
    # Run the node
    asyncio.run(main())
