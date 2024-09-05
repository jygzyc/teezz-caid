import argparse
import os
from utils.log import init_ini_log
from .dependency_finder import DependencyFinder

def build_parser():
    parser = argparse.ArgumentParser(argument_default=None)
    parser.add_argument(
        "--target_lib",
        help="Absolute path to library we want to find dependencies for."
    )
    parser.add_argument(
        "--device_id",
        help="ID of the connected Android device.",
        required=False
    )
    parser.add_argument(
        "-w",
        "--workdir",
        required=True,
        dest="work_dir",
        help="Working directory for intermediate files."
             " Will create a tmpdir if omitted."
    )
    parser.add_argument(
        "-l",
        "--logconfig",
        dest="log_config",
        default="log.ini",
        help="Config file used as logger config. Default value is `log.ini`",
        required=False
    )

    return parser


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    log_directory = os.path.join(os.getcwd(), "logs")
    if not os.path.exists(log_directory):
        os.makedirs(log_directory)
        
    init_ini_log(args.log_config)
    
    # Prepare arguments for DependencyFinder without log_config parameter
    df_args = {k: v for k, v in vars(args).items() if k != "log_config"}
    df = DependencyFinder(**df_args)
    df.run()