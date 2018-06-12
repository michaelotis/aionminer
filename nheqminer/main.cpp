#include <iostream>

#include "version.h"
#include "arith_uint256.h"
#include "primitives/block.h"
#include "streams.h"

#include "MinerFactory.h"

#include "libstratum/StratumClient.h"

#if defined(USE_OCL_XMP) || defined(USE_OCL_SILENTARMY)
#include "../ocl_device_utils/ocl_device_utils.h"
#define PRINT_OCL_INFO
#endif

#include <thread>
#include <chrono>
#include <atomic>
#include <bitset>

#include "speed.hpp"
#include "api.hpp"

#include <boost/program_options.hpp>
#include <boost/log/core/core.hpp>
#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/utility/setup/console.hpp>
#include <boost/log/attributes.hpp>
#include <boost/log/support/date_time.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>


namespace logging = boost::log;
namespace sinks = boost::log::sinks;
namespace src = boost::log::sources;
namespace attrs = boost::log::attributes;
namespace keywords = boost::log::keywords;

#ifdef __linux__
#define __cpuid(out, infoType)\
	asm("cpuid": "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]): "a" (infoType));
#define __cpuidex(out, infoType, ecx)\
	asm("cpuid": "=a" (out[0]), "=b" (out[1]), "=c" (out[2]), "=d" (out[3]): "a" (infoType), "c" (ecx));
#endif

// TODO:
// #1 file logging
// #2 mingw compilation for windows (faster?)
// #3 benchmark accuracy fix: first wait for solvers to init and then measure speed
// #4 Linux fix cmake to generate all in one binary (just like Windows)
// #5 after #4 is done add solver chooser for CPU and CUDA devices (general and per device), example: [-s 0 automatic, -s 1 solver1, -s 2 solver2, ...]

int use_avx = 0;
int use_avx2 = 0;
int use_old_cuda = 1;
int use_old_xmp = 0;

// TODO move somwhere else
MinerFactory *_MinerFactory = nullptr;

// stratum client sig
//static ZcashStratumClient* scSig = nullptr;

// stratum client sig
static AionStratumClient* scSig = nullptr;

extern "C" void stratum_sigint_handler(int signum)
{
	if (scSig) {
		scSig->disconnect();
		delete scSig;
		scSig = nullptr;
	}

	if (_MinerFactory) {
		_MinerFactory->ClearAllSolvers();
		delete _MinerFactory;
		_MinerFactory = nullptr;
	}

	boost::log::core::get()->remove_all_sinks();

	exit(0);
}

// No longer used; kept for historical reference
// void print_help()
// {
// 	std::cout << "Parameters: " << std::endl;
// 	std::cout << "\t-h\t\tPrint this help and quit" << std::endl;
// #ifndef ZCASH_POOL
// 	std::cout << "\t-l [location]\tStratum server:port" << std::endl;
// 	std::cout << "\t-u [username]\tUsername (bitcoinaddress)" << std::endl;
// #else
// 	std::cout << "\t-l [location]\tLocation (eu, usa)" << std::endl;
// 	std::cout << "\t-u [username]\tUsername (Zcash wallet address)" << std::endl;
// #endif
// 	std::cout << "\t-a [port]\tLocal API port (default: 0 = do not bind)" << std::endl;
// 	std::cout << "\t-d [level]\tDebug print level (0 = print all, 5 = fatal only, default: 2)" << std::endl;
// 	std::cout << "\t-b [hashes]\tRun in benchmark mode (default: 200 iterations)" << std::endl;
// 	std::cout << std::endl;
// 	std::cout << "CPU settings" << std::endl;
// 	std::cout << "\t-t [num_thrds]\tNumber of CPU threads" << std::endl;
// 	std::cout << "\t-e [ext]\tForce CPU ext (0 = SSE2, 1 = AVX, 2 = AVX2)" << std::endl;
// 	std::cout << std::endl;
// 	std::cout << "NVIDIA CUDA settings" << std::endl;
// 	std::cout << "\t-ci\t\tCUDA info" << std::endl;
// 	std::cout << "\t-cv [ver]\tSet CUDA solver (0 = djeZo, 1 = tromp)" << std::endl;
// 	std::cout << "\t-cd [devices]\tEnable CUDA mining on spec. devices" << std::endl;
// 	std::cout << "\t-cb [blocks]\tNumber of blocks" << std::endl;
// 	std::cout << "\t-ct [tpb]\tNumber of threads per block" << std::endl;
// 	std::cout << "Example: -cd 0 2 -cb 12 16 -ct 64 128" << std::endl;
// 	std::cout << std::endl;
// 	//std::cout << "OpenCL settings" << std::endl;
// 	//std::cout << "\t-oi\t\tOpenCL info" << std::endl;
// 	//std::cout << "\t-ov [ver]\tSet OpenCL solver (0 = silentarmy, 1 = xmp)" << std::endl;
// 	//std::cout << "\t-op [platf]\tSet OpenCL platform to selecd platform devices (-od)" << std::endl;
// 	//std::cout << "\t-od [devices]\tEnable OpenCL mining on spec. devices (specify plafrom number first -op)" << std::endl;
// 	//std::cout << "\t-ot [threads]\tSet number of threads per device" << std::endl;
// 	////std::cout << "\t-cb [blocks]\tNumber of blocks" << std::endl;
// 	////std::cout << "\t-ct [tpb]\tNumber of threads per block" << std::endl;
// 	//std::cout << "Example: -op 2 -od 0 2" << std::endl; //-cb 12 16 -ct 64 128" << std::endl;
// 	std::cout << std::endl;
// }


void print_cuda_info()
{
#if defined(USE_CUDA_TROMP)
#if USE_CUDA_TROMP
	int num_devices = cuda_tromp::getcount();
#endif

	std::cout << "Number of CUDA devices found: " << num_devices << std::endl;

	for (int i = 0; i < num_devices; ++i)
	{
		std::string gpuname, version;
		int smcount;
#if USE_CUDA_TROMP
		cuda_tromp::getinfo(0, i, gpuname, smcount, version);
#endif
		std::cout << "\t#" << i << " " << gpuname << " | SM version: " << version << " | SM count: " << smcount << std::endl;
	}
#endif
}

void print_opencl_info() {
#ifdef PRINT_OCL_INFO
	ocl_device_utils::print_opencl_devices();
#endif
}

#define MAX_INSTANCES 8 * 2

int cuda_enabled[MAX_INSTANCES] = { 0 };
int cuda_blocks[MAX_INSTANCES] = { 0 };
int cuda_tpb[MAX_INSTANCES] = { 0 };

int opencl_enabled[MAX_INSTANCES] = { 0 };
int opencl_threads[MAX_INSTANCES] = { 0 };
// todo: opencl local and global worksize


void detect_AVX_and_AVX2()
{
	// Fix on Linux
	//int cpuInfo[4] = {-1};
	std::array<int, 4> cpui;
	std::vector<std::array<int, 4>> data_;
	std::bitset<32> f_1_ECX_;
	std::bitset<32> f_7_EBX_;

	// Calling __cpuid with 0x0 as the function_id argument
	// gets the number of the highest valid function ID.
	__cpuid(cpui.data(), 0);
	int nIds_ = cpui[0];

	for (int i = 0; i <= nIds_; ++i)
	{
		__cpuidex(cpui.data(), i, 0);
		data_.push_back(cpui);
	}

	if (nIds_ >= 1)
	{
		f_1_ECX_ = data_[1][2];
		use_avx = f_1_ECX_[28];
	}

	// load bitset with flags for function 0x00000007
	if (nIds_ >= 7)
	{
		f_7_EBX_ = data_[7][1];
		use_avx2 = f_7_EBX_[5];
	}
}


void start_mining(int api_port, const std::string& host, const std::string& port,
	const std::string& user, const std::string& password,
	//ZcashStratumClient* handler, const std::vector<ISolver *> &i_solvers)
	AionStratumClient** handler, const std::vector<ISolver *> &i_solvers)

{
	std::shared_ptr<boost::asio::io_service> io_service(new boost::asio::io_service);

	API* api = nullptr;
	if (api_port > 0)
	{
		api = new API(io_service);
		if (!api->start(api_port))
		{
			delete api;
			api = nullptr;
		}
	}

	AionMiner miner(i_solvers);

	AionStratumClient *sc = new AionStratumClient{
		io_service, &miner, host, port, user, password, 0, 0
	};

	miner.onSolutionFound([&](const EquihashSolution& solution, const std::string& jobid, uint64_t timestamp) {
		return sc->submit(&solution, jobid, timestamp);
	});

	*handler = sc;

	int c = 0;
	while (sc->isRunning()) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		if (++c % 1000 == 0)
		{
			double allshares = speed.GetShareSpeed() * 60;
			double accepted = speed.GetShareOKSpeed() * 60;
			BOOST_LOG_TRIVIAL(info) << CL_YLW "Speed [" << INTERVAL_SECONDS << " sec]: " <<
				speed.GetHashSpeed() << " I/s, " <<
				speed.GetSolutionSpeed() << " Sols/s" <<
				//accepted << " AS/min, " <<
				//(allshares - accepted) << " RS/min"
				CL_N;
		}
		if (api) while (api->poll()) {}
	}

	if (api) delete api;
}


int main(int argc, char* argv[])
{
#if defined(WIN32) && defined(NDEBUG)
	system(""); // windows 10 colored console
#endif
	std::cout << std::endl;
	std::cout << "\t======================= Built by Otis ========================================" << std::endl;
	std::cout << "\t\tEquihash<210,9> CPU & GPU Miner for AION v" STANDALONE_MINER_VERSION << std::endl;
	std::cout << "\tPlease donate: a033b53324486cb230c055edc8138fad840ecfd0ff51d44b091a52a5196bf994" << std::endl;

	std::cout << std::endl;

	std::string location = "aion-us.luxor.tech:3366";
	std::string user = "a033b53324486cb230c055edc8138fad840ecfd0ff51d44b091a52a5196bf994.Aion";
	std::string password = "x";
	int num_threads = 0;
	bool benchmark = false;
	int log_level = 2;
	int num_hashes;
	int api_port = 0;
	int cuda_device_count = 0;
	int cuda_bc = 0;
	int cuda_tbpc = 0;
	int force_cpu_ext = -1;

	signal(SIGINT, stratum_sigint_handler);

	//namespace boost::program_options = boost::program_options; 
	boost::program_options::options_description desc("Options");
	desc.add_options()
		//General settings 
		("help,h", "Print help messages")
		("location,l", boost::program_options::value<std::string>(&location), "Stratum server:port")
		("username,u", boost::program_options::value<std::string>(&user), "Username (Aion Addess)")
		("apiPort,a", boost::program_options::value<int>(&api_port), "Local port (default 0 = do not bind)")
		("level,d", boost::program_options::value<int>(&log_level), "Debug print level (0 = print all, 5 = fatal only, default: 2)")
		("benchmark,b", boost::program_options::value<int>()->implicit_value(200), "Run in benchmark mode (default: 200 iterations)")
		//CPU settings
		("threads,t", boost::program_options::value<int>(&num_threads), "Number of CPU threads")
		("ext,e", boost::program_options::value<int>(&force_cpu_ext), "Force CPU ext (0 = SSE2, 1 = AVX, 2 = AVX2)")
		//NVIDIA settings
		("ci", "Show CUDA info")
		("cv", boost::program_options::value<int>(&use_old_cuda), "CUDA solver (1 = tromp, default=1)")
		("cd", boost::program_options::value<std::vector<int>>()->multitoken()->composing(), "Enable mining on spec. devices")
		("cb", boost::program_options::value<std::vector<int>>()->multitoken()->composing(), "Number of blocks (per device)")
		("ct", boost::program_options::value<std::vector<int>>()->multitoken()->composing(), "Number of threads per block (per device)");

	boost::program_options::variables_map vm;
	try
	{
		boost::program_options::store(boost::program_options::command_line_parser(argc, argv)
			.options(desc)
			.style(
				boost::program_options::command_line_style::unix_style ^
				boost::program_options::command_line_style::allow_guessing |
				boost::program_options::command_line_style::allow_long_disguise
			)
			.run(),
			vm); // can throw 

				 /** --help option
				 */
		boost::program_options::notify(vm); // throws on error, so do after help in case 
											// there are any problems 
		if (vm.count("help") || argc == 1) {
			std::cout << "Aion Reference Miner" << std::endl
				<< desc << std::endl
				<< "Example: -cd 0 2 -cb 12 16 -ct 64 128" << std::endl;
			return 1;
		}

		if (vm.count("benchmark")) {
			benchmark = true;
			num_hashes = vm["benchmark"].as<int>();
		}

		if (vm.count("ci")) {
			print_cuda_info();
			return 1;
		}

		if (vm.count("cd")) {
			std::vector<int> devs = vm["cd"].as<std::vector<int>>();
			for (int i = 0; i < devs.size() && i < MAX_INSTANCES; i++) {
				cuda_enabled[cuda_device_count] = devs[i];
				++cuda_device_count;
			}
		}

		if (vm.count("cb")) {
			std::vector<int> devs = vm["cb"].as<std::vector<int>>();
			for (int i = 0; i < devs.size() && i < MAX_INSTANCES; i++) {
				cuda_blocks[cuda_bc] = devs[i];
				++cuda_bc;
			}
		}

		if (vm.count("ct")) {
			std::vector<int> devs = vm["ct"].as<std::vector<int>>();
			for (int i = 0; i < devs.size() && i < MAX_INSTANCES; i++) {
				cuda_tpb[cuda_tbpc] = devs[i];
				++cuda_tbpc;
			}
		}
	}
	catch (boost::program_options::error& e)
	{
		std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
		std::cerr << desc << std::endl;
		return 0;
	}

	if (force_cpu_ext >= 0)
	{
		switch (force_cpu_ext)
		{
		case 1:
			use_avx = 1;
			break;
		case 2:
			use_avx = 1;
			use_avx2 = 1;
			break;
		}
	}
	else
		detect_AVX_and_AVX2();

	//init_logging init START
	std::cout << "Setting log level to " << log_level << std::endl;
	boost::log::add_console_log(
		std::clog,
		boost::log::keywords::auto_flush = true,
		boost::log::keywords::filter = boost::log::trivial::severity >= log_level,
		boost::log::keywords::format = (
			boost::log::expressions::stream
			<< "[" << boost::log::expressions::format_date_time<boost::posix_time::ptime>("TimeStamp", "%H:%M:%S")
			<< "][" << boost::log::expressions::attr<boost::log::attributes::current_thread_id::value_type>("ThreadID")
			<< "] " << boost::log::expressions::smessage
			)
	);
	boost::log::core::get()->add_global_attribute("TimeStamp", boost::log::attributes::local_clock());
	boost::log::core::get()->add_global_attribute("ThreadID", boost::log::attributes::current_thread_id());
	//init_logging init END

	BOOST_LOG_TRIVIAL(info) << "Using SSE2: YES";
	BOOST_LOG_TRIVIAL(info) << "Using AVX: " << (use_avx ? "YES" : "NO");
	BOOST_LOG_TRIVIAL(info) << "Using AVX2: " << (use_avx2 ? "YES" : "NO");

	try
	{
		_MinerFactory = new MinerFactory();
		if (!benchmark)
		{
			if (user.length() == 0)
			{
				BOOST_LOG_TRIVIAL(error) << "Invalid address. Use -u to specify your address.";
				return 0;
			}

			size_t delim = location.find(':');
			std::string host = delim != std::string::npos ? location.substr(0, delim) : location;
			std::string port = delim != std::string::npos ? location.substr(delim + 1) : "3333";

			start_mining(api_port, host, port, user, password,
				&scSig,
				_MinerFactory->GenerateSolvers(num_threads, cuda_device_count, cuda_enabled, cuda_blocks,
					cuda_tpb));
		}
		else
		{
			Solvers_doBenchmark(num_hashes, _MinerFactory->GenerateSolvers(num_threads, cuda_device_count, cuda_enabled, cuda_blocks, cuda_tpb));
		}
	}
	catch (std::runtime_error& er)
	{
		BOOST_LOG_TRIVIAL(error) << er.what();
	}

	boost::log::core::get()->remove_all_sinks();

	return 0;
}
